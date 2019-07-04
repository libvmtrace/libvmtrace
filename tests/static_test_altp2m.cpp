#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"
#include "sys/LinuxVM.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/async.h"

#include <vector>

using namespace std;
namespace spd = spdlog;

static bool interrupted = false;
static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		// void *array[10];
		// size_t size;

		// // get void*'s for all entries on the stack
		// size = backtrace(array, 10);

		// // print out all the frames to stderr
		// fprintf(stderr, "Error: signal %d:\n", sig);
		// backtrace_symbols_fd(array, size, STDERR_FILENO);
		// exit(1);
	}

	cerr << "Sending kill signal, please wait a few seconds" << endl;
	interrupted = true;
}

class TestListener : public EventListener 
{
	public:
		TestListener(Log& log):_log(log){}
		
		bool callback(const Event* ev, void* data)
		{
			const SyscallEvent* sev = dynamic_cast<const SyscallEvent*>(ev);
			if(sev)
			{
				//cout << sev->GetName() << endl;
				SyscallJson* s = (SyscallJson*)data;
				//cout << dec << s->GetNr() << endl;
				//spd::get("console")->info(s->ToJson());
				_log.log("test", "test", s->ToJson());
				//cout << s->ToJson() << endl;
			}
			return false;
		}
	private:
		Log& _log;
};

int main(int argc, char* argv[]) 
{
	if (argc != 2)
	{
		std::cout << argv[0] << " <vmname>  " << endl;
		return -1;
	}

	auto console = spd::stdout_color_mt<spdlog::async_factory>("console");

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	//sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	SystemMonitor sm(argv[1], true);

	// Altp2m altp2m(sm);
	// sm.SetProfile("/root/profiles/ubuntu/ubuntu1604-4.4.0-124-generic.json");
	// sm.SetBPM(&altp2m, altp2m.GetType());
	// sm.Init();
	// altp2m.Init();
	// sm.Loop();	

	Altp2mBasic altp2mbasic(sm);
	sm.SetBPM(&altp2mbasic, altp2mbasic.GetType());
	sm.Init();
	altp2mbasic.Init();
	sm.Loop();

	// Int3 int3(sm);
	// sm.SetBPM(&int3, int3.GetType());
	// sm.Init();
	// int3.Init();
	// sm.Loop();

	LinuxVM linux(&sm);

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(true));
	
	TestListener* testListener = new TestListener(*log);
	SyscallEvent* read = new SyscallEvent(0, *testListener, false, false, true);

	linux.RegisterSyscall(*read);

    while(!interrupted) 
    {
        sleep(1);
    }

    sm.GetBPM()->DeInit();
    sm.Stop();

    return 0;
}
