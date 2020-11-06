
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>

#include <vector>
#include <chrono>

using namespace std;
using namespace std::chrono;
using namespace libvmtrace;
using namespace libvmtrace::util;
namespace spd = spdlog;

std::shared_ptr<SystemMonitor> sm;
std::shared_ptr<LinuxVM> vm;

static void close_handler(int sig)
{
	cerr << "Sending kill signal, please wait a few seconds" << endl;
	vm = nullptr;
	sm = nullptr;
	exit(sig);
}

class TestListener : public EventListener 
{
	public:
		// TestListener(){}
		TestListener(Log& log):_log(log){}
		
		bool callback(const Event* ev, void* data)
		{
			const SyscallEvent* sev = dynamic_cast<const SyscallEvent*>(ev);
			if (sev)
			{
				time_t currentTime = chrono::system_clock::now().time_since_epoch() / chrono::milliseconds(1);
				// _log.log("test", "test", currentTime+"");
				cout << currentTime << endl;

				SyscallJson* s = (SyscallJson*)data;
				_log.log("test", "test", s->ToJson());
			}

			const auto sys = reinterpret_cast<SyscallBasic*>(data);
			if (sys)
			{
				const auto vmi = sm->Lock();
				std::cout << "Got syscall from " << std::dec << sys->GetPid(vmi) << std::endl;
				sm->Unlock();
			}
			return false;
		}
	private:
		Log& _log;
};

int main(int argc, char* argv[]) 
{
	if (argc != 3)
	{
		std::cout << argv[0] << " <vmname> <pid>" << endl;
		return -1;
	}

	// auto console = spd::stdout_color_mt<spdlog::async_factory>("console");

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	sm = std::make_shared<SystemMonitor>(argv[1], true, true);

	// Altp2m altp2m(sm);
	// sm.SetProfile("/root/profiles/ubuntu/ubuntu1604-4.4.0-124-generic.json");
	// sm.SetBPM(&altp2m, altp2m.GetType());
	// sm.Init();
	// altp2m.Init();
	// sm.Loop();

	// Altp2mBasic altp2mbasic(sm);
	// sm.SetBPM(&altp2mbasic, altp2mbasic.GetType());
	// sm.Init();
	// altp2mbasic.Init();
	// sm.Loop();

	vm = std::make_shared<LinuxVM>(sm);

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(true));

	TestListener* testListener = new TestListener(*log);
	// TestListener* testListener = new TestListener();
	// SyscallEvent* read = new SyscallEvent(0, *testListener, false, false, true);

	vector<SyscallEvent> events;

	for(int i = 1 ; i <= 300 ; i++)
	{
		SyscallEvent s(i, *testListener, false, false, true, static_cast<vmi_pid_t>(std::stoi(argv[2])));
		vm->RegisterSyscall(s);
		events.push_back(s);
	}

	// SyscallEvent* write = new SyscallEvent(1, *testListener, false, false, false);
	// SyscallEvent* open = new SyscallEvent(2, *testListener, true, false, true);
	// SyscallEvent* close = new SyscallEvent(3, *testListener, false, false, true);

	// linux.RegisterSyscall(*read);
	// UNUSED(read);
	// linux.RegisterSyscall(*write);
	// UNUSED(write);
	// linux.RegisterSyscall(*open);
	// UNUSED(open);
	// linux.RegisterSyscall(*close);
	// UNUSED(close);

	cout << "ready" << endl;
	for (;;) { /* nothing */ }
	delete testListener;

	return 0;
}
