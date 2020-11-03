
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <util/LockGuard.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>

#include <vector>

using namespace std;
using namespace libvmtrace;
using namespace libvmtrace::util;
using namespace libvmtrace::net;
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
		
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
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

	const auto sm = std::make_shared<SystemMonitor>(argv[1], true);
	
	// Altp2m altp2m(sm);
	// sm.SetProfile("/root/profiles/ubuntu/ubuntu1604-4.4.0-124-generic.json");
	// sm.SetBPM(&altp2m, altp2m.GetType());
	// sm.Init();
	// altp2m.Init();
	// sm.Loop();

	LinuxVM linux(sm);

	{
		LockGuard guard(sm);
		vector<Process> processes = linux.GetProcessList();

		for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
		{
			if((*it).GetName() != "hping3")
				continue;

			cout << dec << (*it).GetPid() << (*it).GetName() << "="<<(*it).GetPath() << endl;
			pair<addr_t, addr_t> code = linux.GetCodeArea((*it).GetPid());
			cout << hex << code.first << "-" << code.second << endl;

			// addr_t start_p = 0;
			// addr_t end_p = 0;

			// vmi_translate_uv2p(vmi, code.first, (*it).GetPid(), &start_p);
			// vmi_translate_uv2p(vmi, code.second, (*it).GetPid(), &end_p);

			cout << hex << (code.first << 12) << "-" << (code.second << 12) << endl;
			cout << endl;
			vector<OpenFile> openfiles = linux.GetOpenFiles(*it);
			for(vector<OpenFile>::iterator it2 = openfiles.begin() ; it2 != openfiles.end(); ++it2)
			{
				cout << dec << (*it2).fd << " ----" << (*it2).path << endl;
			}

			vector<NetworkConnection> tcpconnections = linux.GetNetworkConnections(*it, TCP);
			for(vector<NetworkConnection>::iterator it2 = tcpconnections.begin() ; it2 != tcpconnections.end(); ++it2)
			{
				cout << "Server: " << dec << (*it2).GetSource() << ":" << (*it2).GetSourcePort() << " ->  ";
				cout << "Client: " << dec << (*it2).GetDestination() << ":" << (*it2).GetDestinationPort() << endl;
			}

		// 	// vector<vm_area> maps = linux.GetMMaps(*it);
		// 	// for(vector<vm_area>::iterator it2 = maps.begin() ; it2 != maps.end(); ++it2)
		// 	// {
		// 	// 	cout << "----" << (*it2).path << ":"<<(*it2).access<<":"<<hex<<(*it2).start<<"-"<<(*it2).end<<"-"<<hex<<(*it2).flags<< endl;
		// 	// }
		}
	}

	// string processesjson = linux.GetProcessesListJson(processes);
	// UNUSED(processesjson);

	ProcessCache pc(linux);
	try
	{
		// const Process& test1 = pc.GetProcessFromPid(1);
		// cout << test1.GetName() << endl;
		// const Process& test2 = pc.GetProcessFromDtb(test1.GetDtb());
		// cout << test2.GetName() << endl;
		// const Process& test3 = pc.GetProcessFromDtbAndRefreshIf(test1.GetDtb(), "systemd");
		// cout << test3.GetName() << endl;
		// const Process& test4 = pc.GetProcessFromPidAndRefreshIf(test1.GetPid(), "systemd");
		// cout << test4.GetName() << endl;
	}
	catch(...)
	{
		cout << "process not found" << endl;
	}

	Log* log = new Log();
	log->RegisterLogger(new StdoutLogger(true));

	TestListener* testListener = new TestListener(*log);
	SyscallEvent* read = new SyscallEvent(0, *testListener, false, false, true);
	SyscallEvent* write = new SyscallEvent(1, *testListener, false, false, true);
	SyscallEvent* open = new SyscallEvent(2, *testListener, true, false, true);
	SyscallEvent* close = new SyscallEvent(3, *testListener, false, false, true);

	// linux.RegisterSyscall(*read);
	UNUSED(read);
	// linux.RegisterSyscall(*write);
	UNUSED(write);
	// linux.RegisterSyscall(*open);
	UNUSED(open);
	// linux.RegisterSyscall(*close);
	UNUSED(close);

	while(!interrupted) 
		sleep(1);

	delete log;

	return 0;
}
