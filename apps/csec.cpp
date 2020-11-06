
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <plugins/Plugins.hpp>

using namespace libvmtrace;
using namespace libvmtrace::util;

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

	_sm = std::make_shared<SystemMonitor>(vm_id, true);
	_linux = std::make_shared<LinuxVM>(_sm);
	ProcessCache pc(*_linux);

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(false));

	SyscallLogger sl(vm_id, *_linux, pc, *log);
	Controller c;
	c.RegisterPlugin(sl);

	std::vector<std::string> params1;
	params1.push_back("0");
	params1.push_back("1");
	params1.push_back("59");
	c.ExecuteCommand("SyscallLogger", "Trace", params1, "0", vm_id);

	while(!interrupted) 
		sleep(1);

	return 0;
}
