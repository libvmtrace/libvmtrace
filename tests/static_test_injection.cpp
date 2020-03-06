
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

#include <vector>

using namespace std;
using namespace libvmtrace;

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
		bool callback(const Event* ev, void* data)
		{
			CodeInjection* s = (CodeInjection*)data;

			// cout << hex << s->result_addr << endl;

			// interrupted = 1;

			cout << "child pid: " << s->child_pid << endl;

			interrupted = 1;

			return true;
		}
};

class TestListener1 : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			// cout << "called" << endl;
			return false;
		}
};

int main(int argc, char* argv[]) 
{
       if (argc != 3)
	{
		std::cout << argv[0] << " <vmname>  <pid>" << endl;
		return -1;
	}

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
	
	Int3 int3(sm);
	sm.SetBPM(&int3, int3.GetType());
	sm.Init();
	int3.Init();

	RegisterMechanism rm(sm);
	sm.SetRM(&rm);
	rm.Init();

	sm.Loop();

	// Altp2m altp2m(sm);
	// sm.SetProfile("/root/profiles/ubuntu/ubuntu1604-4.4.0-124-generic.json");
	// sm.SetBPM(&altp2m, altp2m.GetType());
	// sm.Init();
	// altp2m.Init();
	// sm.Loop();

	// cout << strtol(argv[3], NULL, 16) << endl;

	LinuxVM linux(&sm);

	TestListener tl;
	TestListener1 tl1;

	SyscallEvent se(58, tl1, false, false, false);
	linux.RegisterSyscall(se);

	// if(linux.InvokeCodeInjection(PAGE_FAULT, atoi(argv[2]), strtol(argv[3], NULL, 16), &tl) == VMI_FAILURE)
	// {
	// 	interrupted = 1;
	// }

	// linux.InvokeCodeInjection(FORK_EXEC, atoi(argv[2]), 0, &tl);
	linux.InvokeCommand(atoi(argv[2]), "ping 8.8.8.8", &tl);

	// pair<addr_t, addr_t> section = linux.GetCodeArea(atoi(argv[2]));
	// if(section.first != 0 && section.second != 0)
	// {
	// 	cout << hex << section.first << endl;
	// 	cout << hex << section.second << endl;
	// 	vmi_instance_t vmi = sm.Lock();
	// 	size_t size = 200;//section.first - section.second;
	// 	cout << dec << size << endl;
	// 	char* test = new char[200];

	// 	vmi_read_va(vmi, 400526, atoi(argv[2]), size, test, NULL);
	// 	cout << hexdumptostring(test, size) << endl;

	// 	delete[] test;

	// 	sm.Unlock();
	// }
	// else
	// {
	// 	interrupted = 1;
	// }

	while(!interrupted) 
	{
		sleep(1);
	}
//	sleep(5);
//  sm.GetBPM()->DeInit();
	linux.Stop();
	// sm.Stop();

	return 0;
}
