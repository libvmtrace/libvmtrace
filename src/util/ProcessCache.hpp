
#ifndef __PROCESS_CACHE__
#define __PROCESS_CACHE__

#include <sys/OperatingSystem.hpp>
#include <net/NetworkConnection.hpp>
#include <libvmi/libvmi.h>
#include <vector>
#include <mutex>

namespace libvmtrace
{
	class ProcessCache
	{
		public:
			ProcessCache(OperatingSystem& os) : _os(os), _processes(os.GetProcessList()){}
			
			const Process& GetProcessFromDtb(const addr_t dtb);
			const Process& GetProcessFromPid(const vmi_pid_t pid);

			// <parent pid> mainpid
			//	 \_ <target pid> {return pid}
			//	    \_ .....
			//		   \_ <input pid> pid
			const vmi_pid_t FindParentProcessPidByPid(const int pid, const int mainpid);

			// refresh list if the found process has same name as input, especially when process just fork
			const Process& GetProcessFromDtbAndRefreshIf(const addr_t dtb, const std::string name);
			const Process& GetProcessFromPidAndRefreshIf(const vmi_pid_t pid, const std::string name);
			const Process& GetProcessFromTCPConnection(const net::NetworkConnection* con);

			std::vector<Process> GetProcessesArray()
			{
				return _processes;
			}

			void UpdateList();

		private:
			OperatingSystem& _os;
			std::vector<Process> _processes;

			void FindParentProcessByPid(const vmi_pid_t pid, vmi_pid_t* tmp, const int parent_pid);

			std::recursive_mutex _lock;
	};
}

#endif

