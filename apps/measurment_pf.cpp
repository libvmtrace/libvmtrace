#include <libvmi/libvmi.h>
#include "libvmtrace.hpp"
#include "sys/LinuxVM.hpp"
#include "plugins/Plugins.hpp"

#include <vector>
#include <boost/algorithm/string.hpp>
#include <chrono>



using namespace std;
bool available;
// auto end = std::chrono::high_resolution_clock::now();
std::chrono::high_resolution_clock::time_point start;

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
			auto end = std::chrono::high_resolution_clock::now();
			auto dur = end - start;
			auto ms = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

			cout << "injection took : " << dec << ms << endl;
			//std::ofstream outfile ("/tmp/injecttimes",  std::ofstream::app);
			//outfile << ms << std::endl;
			//outfile.close();
			// return true;
			//cout << "called" << endl;
			available=true;
			return true;
		}
};

TestListener tl;



int main(int argc, char* argv[]) 
{
	if (argc != 5)
	{
		std::cout << argv[0] << " <vmname>  <full path of setting> <logfile> <inject>" << endl;
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

	

	SystemMonitor sm(argv[1], true);
	Int3* int3 = new Int3(sm);
	sm.SetBPM(int3, int3->GetType());
	try {
		sm.Init();
	} catch (...) {
		exit(1);
	}

	RegisterMechanism rm(sm);
	sm.SetRM(&rm);
	//rm.Init();
	
	int3->Init();
	sm.Loop();
	
	LinuxVM linux(&sm);
	ProcessCache pc(linux);

	string vm_id = argv[1];

	Log* log = new Log();
	log->RegisterLogger(new FileLogger(false, argv[3]));

	int inject = atoi(argv[4]);

	//SyscallLogger sl(vm_id, linux, pc, *log, false, true );
	//SyscallLogger sl(vm_id, linux, pc, *log, false, false );
	//ProcessListLogger pll(vm_id, linux, pc, *log);
	
	//Controller c;
	//c.RegisterPlugin(sl);
	//c.RegisterPlugin(pll);

	std::ofstream outfile ("/tmp/start");
	outfile << "my text here!" << std::endl;
	outfile.close();

	std::cout << "get inputs: " << std::endl;
	std::string pidline;
	std::string addrline;
	std::getline(std::cin, addrline);
	std::getline(std::cin, pidline);
	addr_t addr = std::stoul(addrline, nullptr, 16);
	int pid = atoi(pidline.c_str());
	
	std::chrono::high_resolution_clock::time_point x,y;
	x = std::chrono::high_resolution_clock::now();
	linux.PopulatePageFaultAdress(pid, addr, &tl);
	y = std::chrono::high_resolution_clock::now();
	auto dur = y -x;
	auto ms = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();

	//std::ofstream popfile ("/tmp/poptimes",  std::ofstream::app);
	//popfile << ms << std::endl;
	//popfile.close();
	cout << "populate time\t" << ms <<  endl;


	std::string goline;
	std::getline(std::cin, goline);
	
	std::cout << "go\t" << hex << addr << endl;


	if (inject == 1) {
		available = false;


		start = std::chrono::high_resolution_clock::now();
		cout << "inject " << endl;
		linux.InvokePageFault(1);
		//	available=true;
		while(!available) { 
			sleep(1); 
			cout << "available: " << available << std::endl;
		}
	} else if (inject == 2) {
		linux.InvokeCommand(pid, "touch /tmp/test", &tl);
		sleep(30);
	}
	
#if 0
	while(!available) { 
		sleep(1); 
		cout << "available: " << available << std::endl;
	}
	status_t status;
	uint32_t cnt = 10;
	vmi_instance_t vmi = sm.Lock();
	status = vmi_read_32_va(vmi, addr, pid, &cnt);
	sm.Unlock();
	if (status == VMI_SUCCESS)
		cout << "SUCCESS " << endl;
	else if (status == VMI_FAILURE)
		cout << "FAIL " << endl;
#endif

	std::string timeline;
	std::getline(std::cin, timeline);
	
	std::cout << "comp tim\t " << timeline << endl;
	linux.Stop();
	sm.Stop();
	sleep(3);

	return 0;
}
