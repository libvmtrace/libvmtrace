
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <plugins/Plugins.hpp>

using namespace libvmtrace;
using namespace libvmtrace::util;

LinuxVM* _linux;
SystemMonitor* _sm;

static bool interrupted = false;
static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		_sm->GetBPM()->DeInit();
		_sm->Stop();
	}

	interrupted = true;
}

int main(int argc, char* argv[]) 
{
	if (argc != 2)
	{
		std::cout << argv[0] << " <vmname>" << std::endl;
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

	SystemMonitor sm(vm_id, true);
	_sm = &sm;

	Int3 *int3 = new Int3(sm);
	sm.SetBPM(int3, int3->GetType());
	sm.Init();
	int3->Init();
	sm.Loop();

	LinuxVM linux(&sm);
	_linux = &linux;
	ProcessCache pc(linux);

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(false));

	SyscallLogger sl(vm_id, linux, pc, *log);
	Controller c;
	c.RegisterPlugin(sl);

	std::vector<std::string> params1;
	params1.push_back("0");
	params1.push_back("1");
	params1.push_back("59");
	c.ExecuteCommand("SyscallLogger", "Trace", params1, "0", vm_id);

	while(!interrupted) 
	{
		sleep(1);
	}

	linux.Stop();
	sm.Stop();

	return 0;
}
