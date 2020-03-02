
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <openssl/sha.h>
#include <chrono>

using namespace std;
using namespace libvmtrace;

static bool interrupted = false;

LinuxVM* _linux;
SystemMonitor* _sm;

char* binary;
vmi_pid_t pid;
size_t text_offset;

void process_hash(vmi_instance_t vmi, LinuxVM& linux);

static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		_linux->Stop();
	}

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
			vmi_instance_t vmi = _sm->Lock();
			process_hash(vmi, *_linux);
			_sm->Unlock();
			return true;
		}
};

TestListener tl;

string sha256(char* str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, sizeof(str) - 1);
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void process_hash(vmi_instance_t vmi, LinuxVM& linux)
{
	char* buff = new char[4096];
	ifstream infile(binary, ifstream::binary);
	infile.seekg(text_offset);

	// do the magic
	vector<Process> processes = linux.GetProcessList();
	for(vector<Process>::iterator it = processes.begin() ; it != processes.end() ; ++it)
	{
		if((*it).GetPid() == pid)
		{
			cout << dec << (*it).GetPid() << endl;

			char* buf = new char[4096];

			vector<vm_area> maps = linux.GetMMaps(*it);

			access_context_t _ctx_dtb;
			_ctx_dtb.translate_mechanism = VMI_TM_PROCESS_DTB;
			_ctx_dtb.dtb = (*it).GetDtb();

			bool allresolved = true;

			for(vector<vm_area>::iterator it2 = maps.begin() ; it2 != maps.end(); ++it2)
			{
				if(((*it2).flags & VM_EXEC) == VM_EXEC && (*it2).path == "/usr/sbin/sshd")
				{
					addr_t test = (*it2).start;
					addr_t test2 = (*it2).end;

					cout << "========= " << (*it2).path << " ========= (" << hex << test <<" - " << test2 << ")" << endl;

					for(addr_t a = test + text_offset ; a < test2 ; a += 4096)
					{

						cout << hex << a << " - " << (a+4096) << endl;

						_ctx_dtb.addr = a-4096;

						status_t status = vmi_read(vmi, &_ctx_dtb, 4096, buf, NULL);
						infile.read(buff, 4096);

						cout << (status == VMI_SUCCESS ? "S" : "F") << " : " << sha256(buf) << " - " << sha256(buff) << endl;
						if(status == VMI_FAILURE)
						{
							allresolved = false;
							linux.PopulatePageFaultAdress((*it).GetPid(), a, &tl);
						}
						// break;
					}
				}
			}

			if(!allresolved)
			{
				linux.InvokePageFault(5);
			}

			delete[] buf;
		}
	}

	delete[] buff;
}

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		cout << argv[0] << " <vmname> <pid> <binary compare>" << endl;
		return -1;
	}

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	SystemMonitor sm(argv[1], true);
	_sm = &sm;

	Int3 int3(sm);
	sm.SetBPM(&int3, int3.GetType());
	sm.Init();
	int3.Init();

	RegisterMechanism rm(sm);
	sm.SetRM(&rm);
	rm.Init();

	sm.Loop();

	LinuxVM linux(&sm);
	_linux = &linux;

	vmi_instance_t vmi = sm.Lock();
	UNUSED(vmi);

	ElfHelper eh;
	int len = 0;
	char* binaryMap;
	binary = argv[3];
	binaryMap = eh.map_file(argv[3], 0, &len);
	text_offset = eh.get_section_offset(binaryMap, ".text");

	pid = atoi(argv[2]);
	process_hash(vmi, linux);

	sm.Unlock();

	while(!interrupted) 
	{
		sleep(1);
	}

	linux.Stop();
	sm.Stop();
}
