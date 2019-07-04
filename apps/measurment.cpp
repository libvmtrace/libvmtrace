#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"
#include "sys/LinuxVM.hpp"
#include "plugins/Plugins.hpp"

#include <vector>
#include <boost/algorithm/string.hpp>


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

class TestListener : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			// CodeInjection* ci = (CodeInjection*) data;
			// auto end = std::chrono::high_resolution_clock::now();
			// auto dur = end - ci->start;
			// auto ms = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

			// cout << "done page fault for : " << dec << ci->result_addrs.size() << " pages took : " << dec << ms << endl;
			// return true;
			cout << "called" << endl;
			return true;
		}
};

TestListener tl;



int main(int argc, char* argv[]) 
{
	if (argc != 4)
	{
		std::cout << argv[0] << " <vmname>  <full path of setting> <logfile>" << endl;
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
	sigaction(SIGUSR1, &act, NULL);

	// Setting setting("/root/setting_test.json");
	Setting setting(argv[2]);

	string kafka_url = setting.GetStringValue("kafka_url");
	string command_topic = setting.GetStringValue("kafka_command_topic");

	SystemMonitor sm(argv[1], true);
	Int3* int3 = new Int3(sm);
	sm.SetBPM(int3, int3->GetType());
	sm.Init();

	RegisterMechanism rm(sm);
	sm.SetRM(&rm);
	
	int3->Init();
	sm.Loop();


	
	LinuxVM linux(&sm);

	ProcessCache pc(linux);

	string vm_id = argv[1];

	Log* log = new Log();
	log->RegisterLogger(new FileLogger(false, argv[3]));
	// KafkaLogger* kl = new KafkaLogger(kafka_url);
	// UNUSED(kl);
	// log->RegisterLogger(kl);
	
	std::string with_ret = setting.GetStringValue("with_ret");
	cout << "[" << with_ret << "]" << endl;
	bool ret=false;
	if (with_ret == "1") ret = true;
	SyscallLogger sl(vm_id, linux, pc, *log, false, ret );
	
	ProcessListLogger pll(vm_id, linux, pc, *log);
	ProcessChangeLogger pcl(vm_id, linux, *log);
	
	Controller c;
	c.RegisterPlugin(sl);
	c.RegisterPlugin(pll);
	c.RegisterPlugin(pcl);


	vector<string> params1;
	vector<string> params2;


	std::string syscalls = setting.GetStringValue("syscalls");
	if (syscalls.length() !=0) {
		cout << "syscall config [" << syscalls << "] "<< endl;
		if (syscalls == "all") {
			for (int i=0; i<512; i++) {
				params1.push_back(std::to_string(i));
			}
		} else {
			boost::split(params1, syscalls, boost::is_any_of(","));
		}

		c.ExecuteCommand("SyscallLogger", "Trace", params1, "0", vm_id);
	}
	
	std::string proclist = setting.GetStringValue("proclist");
	if (proclist != "0") {
		vector<string> p;
		p.push_back(proclist);
		c.ExecuteCommand("ProcessListLogger", "EnablePeriodic", p, "1", vm_id);
	}
	std::string cr3intercept = setting.GetStringValue("cr3");
	if (cr3intercept == "1") {
		//rm.Init();
		vector<string> pcv;
		c.ExecuteCommand("ProcessChangeLogger", "Enable", pcv, "1", vm_id);
	}

	// params2.push_back("1000");
	// c.ExecuteCommand("ProcessListLogger", "EnablePeriodic", params2, "0", vm_id);

	std::ofstream outfile ("/tmp/start");
	outfile << "my text here!" << std::endl;
	outfile.close();
	cout << "initialized" << endl;


	

	
	while(!interrupted) 
	{
		 sleep(1);
	}

	

	linux.Stop();
	sm.Stop();
	sleep(3);

	return 0;
}
