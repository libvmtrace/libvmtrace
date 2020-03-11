
#include <sys/LinuxELFInjector.hpp>
#include <util/LockGuard.hpp>
#include <sys/LinuxVM.hpp>
#include <memory>

namespace libvmtrace
{
	using namespace util;

	LinuxELFInjector::LinuxELFInjector(std::shared_ptr<SystemMonitor> sm, std::shared_ptr<LinuxVM> vm,
				Process parent) : sm(sm), vm(vm), parent(parent), finished(false)
	{
		LockGuard guard(sm);

		inject_listener = std::make_unique<injection_listener>(*this, std::bind(&LinuxELFInjector::on_injection,
					this, std::placeholders::_1, std::placeholders::_2));
		cr3_listener = std::make_unique<injection_listener>(*this, std::bind(&LinuxELFInjector::on_cr3_change,
					this, std::placeholders::_1, std::placeholders::_2));
		mmap_listener = std::make_unique<injection_listener>(*this, std::bind(&LinuxELFInjector::on_mmap_break,
					this, std::placeholders::_1, std::placeholders::_2));
		execveat_listener = std::make_unique<injection_listener>(*this, std::bind(&LinuxELFInjector::on_execveat,
					this, std::placeholders::_1, std::placeholders::_2));
		last_chance_listener = std::make_unique<injection_listener>(*this, std::bind(&LinuxELFInjector::on_last_chance,
					this, std::placeholders::_1, std::placeholders::_2));

		vmi_get_kernel_struct_offset(guard.get(), "task_struct", "thread", &offsets.thread_struct);
		vmi_get_kernel_struct_offset(guard.get(), "thread_struct", "sp0", &offsets.sp0);
		vmi_get_kernel_struct_offset(guard.get(), "pt_regs", "ip", &offsets.ip);
	}

	Process LinuxELFInjector::inject_executable(std::shared_ptr<std::vector<uint8_t>> executable)
	{
		using namespace std::chrono_literals;

		// store pointer to executable so the event callbacks can access them later.
		this->executable = executable;

		// invoke process fork.
		vm->InvokeCommand(parent.GetPid(), "while true; do sleep 5; done", inject_listener.get());
		
		// this should be a mutex + condition variable instead, but meh.
		do { std::this_thread::sleep_for(4ms); } while(!finished);

		// return pid.
		return *child;
	}

	bool LinuxELFInjector::on_injection(const Event* event, void* data)
	{	
		const auto plist = vm->GetProcessList();
		const auto result = std::find_if(plist.begin(), plist.end(),
			[&](const auto& p) -> bool { return p.GetPid() == ((CodeInjection*) data)->child_pid; });
		if (result == plist.end())
		{
			throw std::runtime_error("Failed to find forked process.");
			return false;
		}

		// store off child process.
		child = std::make_unique<Process>(*result);
		forked = true;

		// set a callback for the context switch back to the usermode process.
		cr3_change = std::make_unique<ProcessChangeEvent>(*cr3_listener);
		sm->GetRM()->InsertRegisterEvent(cr3_change.get());
		return true;
	}

	bool LinuxELFInjector::on_cr3_change(const Event* event, void* data)
	{
		assert(forked);

		// access vmi event and target process.
		LockGuard guard(sm);
		const auto vmi_event = reinterpret_cast<const vmi_event_t* const>(data);

		vmi_pid_t pid;
		if (vmi_dtb_to_pid(guard.get(), vmi_event->reg_event.value, &pid) != VMI_SUCCESS
				|| pid != child->GetPid())
			return false;
		
		// page table duplication is not done yet when the first cr3 changes happen,
		// ideally we want a hook in the kernel to notify us when we are ready,
		// but this will have to do for now.
		if (++page_loop < 0x10)
			return false;

		// guest os scheduler just context switched our vcpu, clear out the cache.
		vmi_v2pcache_flush(guard.get(), ~0ull);

		// store off the 'duplicated' child process now.
		const auto plist = vm->GetProcessList();
		const auto result = std::find_if(plist.begin(), plist.end(),
			[&](const auto& p) -> bool { return p.GetParentPid() == parent.GetPid(); });

		if (result == plist.end())
		{
			throw std::runtime_error("Failed to find forked process.");
			return false;
		}

		child = std::make_unique<Process>(*result);
		assert(child->GetDtb() != parent.GetDtb());

		// get user-mode stack pointer.
		addr_t stack_ptr{};
		if (vmi_read_addr_va(guard.get(), child->GetTaskStruct() + offsets.thread_struct + offsets.sp0,
					0, &stack_ptr) != VMI_SUCCESS)
			throw std::runtime_error("Failed to retrieve user-mode stack pointer.");

		// access registers and find the to-be instruction pointer of the thread on process entry.
		addr_t pt_regs_ptr = stack_ptr - 0xA8; // TODO: maybe get this offset dynamically?
		addr_t ip{};
		if (vmi_read_addr_va(guard.get(), pt_regs_ptr + offsets.ip, 0, &ip) != VMI_SUCCESS)
			throw std::runtime_error("Failed to get instruction pointer at thread execution.");

		// this calculation is a bit sketchy, in theory the displaced instruction pointer might
		// be outside of the allocation bounds. however because most linkers position both the .text
		// section and each function with a certain alignment, this should never happen.
		// let's assume this holds true and store off the code at the specified offset.
		start = ip - shellcode.displacement;
		stored_bytes.resize(shellcode.size);
		if (vmi_read_va(guard.get(), start, child->GetPid(), shellcode.size,
					stored_bytes.data(), nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Failed to store off instructions at the offsetted pointer.");

		// determine at which address the interrupt will occur.
		const auto mmap_va = start + shellcode.interrupt_mmap;
		const auto last_chance_va = start + 0xE1;
		if (vmi_translate_uv2p(guard.get(), mmap_va, child->GetPid(), &mmap) != VMI_SUCCESS
				|| vmi_translate_uv2p(guard.get(), last_chance_va, child->GetPid(), &last_chance) != VMI_SUCCESS)
			throw std::runtime_error("Could not translate virtual interrupt addresses to physical memory.");

		// transfer the shellcode first.
		if (vmi_write_va(guard.get(), start, child->GetPid(), shellcode.size,
					const_cast<char*>(shellcode.data), nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Failed to write shellcode to target process.");

		// write the size of executable at the start of the shellcode.
		auto exec_size = static_cast<uint64_t>(executable->size());
		if (vmi_write_64_va(guard.get(), start, child->GetPid(), &exec_size) != VMI_SUCCESS)
			throw std::runtime_error("Failed to write executable size.");

		// everything in its place, set up callback for the interrupts the shellcode will trigger.
		std::cout << "CR3 change occured, placed mmap breakpoint." << std::endl << std::flush;
		mmap_break = std::make_unique<ProcessBreakpointEvent>("MMAP BP", 0, mmap, *mmap_listener);
		sm->GetBPM()->InsertBreakpoint(mmap_break.get());
		last_chance_break = std::make_unique<ProcessBreakpointEvent>("LAST CHANCE BP", 0, last_chance, *last_chance_listener);
		sm->GetBPM()->InsertBreakpoint(last_chance_break.get());

		// remove the cr3 listener that called us.
		return true;
	}

	bool LinuxELFInjector::on_mmap_break(const Event* event, void* data)
	{
		assert(forked);

		// access the event data.
		LockGuard guard(sm);
		const auto bp_event = reinterpret_cast<const BPEventData* const>(data);

		// make sure we are at the break point.
		if (!bp_event->beforeSingleStep || bp_event->paddr != mmap)
			return false;

		// write executable to shared memory mapped region.
		if (vmi_write_va(guard.get(), bp_event->regs.r13, child->GetPid(),
				executable->size(), executable->data(), nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Failed to write executable to memory.");

		// step over the breakpoint and execute memory.
		if (vmi_set_vcpureg(guard.get(), bp_event->regs.rip + 1, RIP,
				bp_event->vcpu) != VMI_SUCCESS)
			throw std::runtime_error("Failed to step over breakpoint.");

		// set marker that image was sent to the guest.
		mapped = true;

		// attach syscall breakpoint.
		execveat_call = std::make_unique<SyscallEvent>(offsets.execveat_index,
				*execveat_listener, false, false, false);
		vm->RegisterSyscall(*execveat_call);
		return true;
	}
	
	void debug_cpu(vmi_instance_t vmi, vmi_pid_t pid, const BPEventData* data)
	{
		char test[200];
		vmi_read_va(vmi, data->regs.rip, pid, 200, test, nullptr);
		std::cout << "RIP [0x" << std::hex << data->regs.rip << "] dump: "
			<< std::endl << hexdumptostring(test, 200) << std::endl;

		uint8_t rsi;
		vmi_read_va(vmi, data->regs.rsi, pid, 1, &rsi, nullptr);

		std::cout << "Registers: " << std::endl
			<< "RAX: 0x" << std::hex << data->regs.rax << std::endl
			<< "RDI: 0x" << std::hex << data->regs.rdi << std::endl
			<< "RSI: 0x" << std::hex << data->regs.rsi << std::endl
			<< "RSI->: 0x" << std::hex << (uint64_t) rsi << std::endl
			<< "RDX: 0x" << std::hex << data->regs.rdx << std::endl
			<< "R10: 0x" << std::hex << data->regs.r10 << std::endl
			<< "R8: 0x" << std::hex << data->regs.r8 << std::endl
			<< "R9: 0x" << std::hex << data->regs.r9 << std::endl
			<< "R12: 0x" << std::hex << data->regs.r12 << std::endl
			<< "R13: 0x" << std::hex << data->regs.r13 << std::endl;
	}
	
	bool LinuxELFInjector::on_last_chance(const Event* event, void* data)
	{
		LockGuard guard(sm);
		//const auto bp_event = reinterpret_cast<const BPEventData* const>(data);
		//debug_cpu(guard.get(), child->GetPid(), bp_event); 
		return true;
	}

	bool LinuxELFInjector::on_execveat(const Event* event, void* data)
	{
		assert(forked);
		assert(mapped);

		// TODO: make sure this actually our call.
		
		// access the event data.
		LockGuard guard(sm);

		// write back original instructions.
		// note that we don't have to take the instruction pointer into account,
		// because the syscall will not return on success.
		// we need to restore the original instructions because the same physical
		// memory might be mapped into multiple processes.
		if (vmi_write_va(guard.get(), start, child->GetPid(), stored_bytes.size(),
					stored_bytes.data(), nullptr) != VMI_SUCCESS)
			throw std::runtime_error("Failed to restore original instructions.");

		// finish mapping process.
		finished = true;
		return true;
	}

	bool LinuxELFInjector::injection_listener::callback(const Event* event, void* data)
	{
		return fn(event, data);
	}
}
