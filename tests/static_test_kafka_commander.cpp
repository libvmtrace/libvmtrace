#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"
#include "sys/LinuxVM.hpp"

#include "Plugins.hpp"

#include <vector>

using namespace std;

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

class P1 : public Plugin
{
	public:
		const string ExecuteCommand(const string command, 
									const vector<string> params,
									const string command_id,
									const string vm_id)
		{
			return "OK";
		}

		const string GetName() const
		{
			return "P1";
		}

		const vector<string> GetListCommands() const
		{
			return _commands;
		}

		const void Stop()
		{
			cout << "STOP" << endl;
		}

	private:
		vector<string> _commands;
};

int main(int argc, char* argv[]) 
{
	if (argc != 3)
	{
		std::cout << argv[0] << " <vmname>  <full path of setting>" << endl;
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

	// Setting setting("/root/setting_test.json");
	Setting setting(argv[2]);
	
	P1 p1;
	Controller c;
	c.RegisterPlugin(p1);
	KafkaCommander kc(setting.GetStringValue("kafka_url"), setting.GetStringValue("topic"), c, argv[1]);

	while(!interrupted) 
	{
		kc.GetCommands();
		//sleep(1);
	}

	return 0;
}
