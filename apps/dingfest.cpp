#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"
#include "sys/LinuxVM.hpp"
#include "plugins/Plugins.hpp"

#include <vector>

using namespace std;

static bool interrupted = false;
static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		
	}

	cerr << "Sending kill signal, please wait a few seconds" << endl;
	interrupted = true;
}



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

	string kafka_url = setting.GetStringValue("kafka_url");
	string command_topic = setting.GetStringValue("kafka_command_topic");

	SystemMonitor sm(argv[1], true);
	Int3* int3 = new Int3(sm);
	sm.SetBPM(int3, int3->GetType());
	sm.Init();
	int3->Init();
	sm.Loop();
	
	LinuxVM linux(&sm);
	ProcessCache pc(linux);

	string vm_id = argv[1];

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(true));
	// KafkaLogger* kl = new KafkaLogger(kafka_url);
	// UNUSED(kl);
	// log->RegisterLogger(kl);

	SyscallLogger sl(vm_id, linux, pc, *log);
	ProcessListLogger pll(vm_id, linux, pc, *log);
	
	Controller c;
	c.RegisterPlugin(sl);
	c.RegisterPlugin(pll);
	KafkaCommander kc(kafka_url, command_topic, c, argv[1]);

	vector<string> params1;
	vector<string> params2;
	params1.push_back("0");
	params1.push_back("1");
	params1.push_back("2");
	// params1.push_back("59");

	c.ExecuteCommand("SyscallLogger", "Trace", params1, "0", vm_id);
	// c.ExecuteCommand("ProcessListLogger", "GetProcessList", params1, "0", vm_id);

	// params2.push_back("1000");
	// c.ExecuteCommand("ProcessListLogger", "EnablePeriodic", params2, "0", vm_id);

	while(!interrupted) 
	{
		kc.GetCommands();
		// sleep(1);
	}

	linux.Stop();
	sm.Stop();

	return 0;
}