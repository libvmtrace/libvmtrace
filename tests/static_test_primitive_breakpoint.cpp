
#include <libvmtrace.hpp> 
#include <sys/LinuxVM.hpp>
#include <util/LockGuard.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <cassert>
#include <algorithm>
#include <optional>

using namespace libvmtrace;
using namespace util;

// vmtrace wrapper.
std::shared_ptr<SystemMonitor> sm;
std::shared_ptr<LinuxVM> vm;

class TestListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			const auto bp_event = reinterpret_cast<BPEventData* const>(data);
			LockGuard guard(sm);
			vmi_set_vcpureg(guard.get(), 1, RAX, bp_event->vcpu);
			return false;
		}
};

// shutdown routine.
void shutdown(int sig)
{
	vm = nullptr;
	sm = nullptr;

	exit(sig);
}

// TODO: look for a process to inject code into here.
std::optional<Process> find_suitable_process(const vmi_pid_t pid)
{
	const auto plist = vm->GetProcessList();
	const auto result = std::find_if(plist.begin(), plist.end(),
			[&](const auto& p) -> bool { return p.GetPid() == pid; });
	
	if (result == plist.end())
		return std::nullopt;

	return *result;
}

// main routine of the shared library / executable.
int main(int argc, char** argv)
{
	// set up event handlers.
	struct sigaction act;
	act.sa_handler = shutdown;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, nullptr);
	sigaction(SIGTERM, &act, nullptr);
	sigaction(SIGINT, &act, nullptr);
	sigaction(SIGALRM, &act, nullptr);
	sigaction(SIGPIPE, &act, nullptr);
	sigaction(SIGSEGV, &act, nullptr);

	// print usage.
	if (argc < 4)
	{
		std::cerr << "USAGE: " << argv[0] << " [VM_NAME] [PID] [ADDR]" << std::endl;
		return 1;
	}

	// create vmtrace wrapper objects.
	sm = std::make_shared<SystemMonitor>(argv[1], true);

	// initialize vmtrace and delegate.
	try
	{
		vm = std::make_unique<LinuxVM>(sm);
		std::cout << "Successfully initiated VMI on " << argv[1] << "!" << std::endl;

		const auto process = find_suitable_process(static_cast<vmi_pid_t>(std::stoi(argv[2])));
		if (!process.has_value())
			throw std::runtime_error("Failed to retrieve suitable process from VM.");

		std::cout << "Found process: " << process->GetName() << std::endl;
		
		const auto addr = static_cast<addr_t>(std::stoi(argv[3]));
		TestListener test_listener{};
		const auto bp = std::make_unique<ProcessBreakpointEvent>("Test", process->GetPid(), addr, test_listener);
		sm->GetBPM()->InsertBreakpoint(bp.get());

		std::cout << "Set breakpoint, press any key to undo it!" << std::endl;
		std::cin.get();
		sm->GetBPM()->RemoveBreakpoint(bp.get());

		std::cout << "Restored original!" << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		sm->Unlock();
	}
	catch (...)
	{
		std::cerr << "Unknown error occured." << std::endl;
	}
	
	// clear up resources.
	shutdown(0);
	return 0;
}

