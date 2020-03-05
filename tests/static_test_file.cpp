
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

using namespace std;
using namespace libvmtrace;

int main(int argc, char* argv[]) 
{
	SystemMonitor sm("file", true);
	sm.InitFile("/usr/src/libvmi/examples/a");
	vmi_instance_t vmi = sm.Lock();

	addr_t syscall_addr_pa = 0;
	vmi_translate_kv2p(vmi, 0xffffffff8184fa50, &syscall_addr_pa);
	cout << hex << syscall_addr_pa << endl;

	char temp[100];
	if(vmi_read_pa(vmi, 0x10867a0, 100, temp, NULL) == VMI_FAILURE)
		cout << "fail" << endl;
	else
		cout << hexdumptostring(temp, 100) << endl;

	sm.Unlock();
	sm.Stop();
}
