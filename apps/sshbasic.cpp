#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <util/LockGuard.hpp>

#include <iostream>
#include <vector>
#include <boost/bind.hpp>
#include <algorithm>
#include <chrono>
#include <fstream>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>

using namespace std;
using namespace spdlog;
using namespace rapidjson;
using namespace libvmtrace;
using namespace libvmtrace::util;
using namespace libvmtrace::net;

std::shared_ptr<SystemMonitor> _sm;
std::shared_ptr<LinuxVM> _linux;

static bool interrupted = false;
static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		_linux = nullptr;
		_sm = nullptr;
	}

	interrupted = true;
}
bool postInserted = false;
class PostAuthPasswordListener : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			BPEventData* a = (BPEventData*) data;
			if(!a->beforeSingleStep) return false;
			
			LockGuard guard(_sm);
			cout << "RET: " << a->regs.rax << endl;

			vmi_set_vcpureg(guard.get(), 1, RAX, a->vcpu);
			postInserted = false;
			return true;
		}
};

PostAuthPasswordListener post_listener{};
std::unique_ptr<ProcessBreakpointEvent> post;
class AuthPasswordListener : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			/*BPEventData* a = (BPEventData*) data;
			if (a->beforeSingleStep) return false;

			LockGuard guard(_sm);
			addr_t dtb = a->regs.cr3 & ~0x1FFF;*/
			
			/*addr_t pw_pa = 0;
			vmi_pagetable_lookup(guard.get(), dtb, a->regs.rsi, &pw_pa);
			const auto pw = vmi_read_str_pa(guard.get(), pw_pa);
			std::cout << "PW: " << pw << std::endl;
			free(pw);*/
			
			/*if (!post)
			{
				addr_t stack_addr_pa = 0;
				vmi_pagetable_lookup(guard.get(), dtb, a->regs.rsp, &stack_addr_pa);

				if (stack_addr_pa != 0)
				{
					addr_t return_addr_va = 0;
					vmi_read_64_pa(guard.get(), stack_addr_pa, &return_addr_va);
					addr_t return_addr_pa = 0;
					vmi_pagetable_lookup(guard.get(), dtb, return_addr_va, &return_addr_pa);

					if (return_addr_pa != 0)
					{
						post = std::make_unique<ProcessBreakpointEvent>("authPasswordPostEvent", 0, return_addr_pa, post_listener);
						//_sm->GetBPM()->InsertBreakpoint(post.get());
					}
				}
			}

			if(!postInserted) {
				_sm->GetBPM()->InsertBreakpoint(post.get());
				postInserted = true;
			}*/

			return false;
		}
};

class TestListener : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			cout << "TEST HIT CLONE SYSCALL" << endl;
			return false;
		}
};

int main(int argc, char* argv[]) {
	if (argc != 3)
	{
		std::cout << argv[0] << " <vmname> <sshd parent pid>" << std::endl;
		return -1;
	}
	std::string vm_id = argv[1];

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	//sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	_sm = std::make_shared<SystemMonitor>(vm_id, true, false, "/tmp/one-1393/vmi-sock");
	_linux = std::make_shared<LinuxVM>(_sm);

	addr_t va = 0;
	addr_t pa = 0;

	vector<Process> processes = _linux->GetProcessList();
	for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
	{
		if((*it).GetName() == "sshd" && (*it).GetPid() == stoi(argv[2])) {
			va = _linux->GetSymbolAddrVa("/tmp/sshd", *it, "auth_password", true);

			vmi_instance_t vmi = _sm->Lock();
			vmi_translate_uv2p(vmi, va, (*it).GetPid(), &pa);
			_sm->Unlock();

			cout << "VA HEX : " << hex << va << endl;
			cout << "PA HEX : " << hex << pa << endl;
		}
	}

	AuthPasswordListener listener{};
	const auto bp = std::make_unique<ProcessBreakpointEvent>("AuthPassword", 0, pa, listener, true);
	
	_sm->GetBPM()->InsertBreakpoint(bp.get());
	cout << "BREAKPOINT INSERTED" << endl;

	/*TestListener testListener{};
	const auto sClone = new SyscallEvent(56, testListener, true, false, false);
	_linux->RegisterSyscall(*sClone);*/
	
	while(!interrupted) 
		sleep(1);

	_sm->GetBPM()->RemoveBreakpoint(bp.get());
	if(post)
		_sm->GetBPM()->RemoveBreakpoint(post.get());
	cout << "BREAKPOINT RESTORED" << endl;

	return 0;
}
