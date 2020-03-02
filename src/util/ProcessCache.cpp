
#include <util/ProcessCache.hpp>

using namespace std;

namespace libvmtrace
{
	void ProcessCache::UpdateList()
	{
		{
			lock_guard<recursive_mutex> lock(_lock);
			_processes = _os.GetProcessList();
		}
	}

	const Process& ProcessCache::GetProcessFromDtb(const addr_t dtb)
	{
		addr_t dtb1 = dtb & ~0x1fff;
		bool found = false;

		{
			lock_guard<recursive_mutex> lock(_lock);
			for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
			{
				if((*it).GetDtb() == dtb || (*it).GetDtb() == dtb1)
				{
					found = true;
					return (*it);
				}
			}
		}
		
		if(!found)
		{
			UpdateList();
			
			{
				lock_guard<recursive_mutex> lock(_lock);
				for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
				{
					if((*it).GetDtb() == dtb || (*it).GetDtb() == dtb1)
					{
						return (*it);
					}
				}
			}
		}

		throw runtime_error("could not find process");
	}

	const Process& ProcessCache::GetProcessFromPid(const vmi_pid_t pid)
	{
		bool found = false;

		{
			lock_guard<recursive_mutex> lock(_lock);
			for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
			{
				if((*it).GetPid() == pid)
				{
					found = true;
					return (*it);
				}
			}
		}
		

		if(!found)
		{
			UpdateList();

			{
				lock_guard<recursive_mutex> lock(_lock);
				for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
				{
					if((*it).GetPid() == pid)
					{
						return (*it);
					}
				}
			}
		}

		throw runtime_error("could not find process");
	}

	const Process& ProcessCache::GetProcessFromDtbAndRefreshIf(const addr_t dtb, const string name)
	{
		const Process& p = GetProcessFromDtb(dtb);
		if(p.GetName() == name)
		{
			UpdateList();

			const Process& p2 = GetProcessFromDtb(dtb);
			return p2;
		}
		else
		{
			return p;
		}
	}

	const Process& ProcessCache::GetProcessFromPidAndRefreshIf(const vmi_pid_t pid, const string name)
	{
		const Process& p = GetProcessFromPid(pid);
		if(p.GetName() == name)
		{
			UpdateList();
			
			const Process& p2 = GetProcessFromPid(pid);
			return p2;
		}
		else
		{
			return p;
		}
	}

	const Process& ProcessCache::GetProcessFromTCPConnection(const NetworkConnection* con)
	{
		{
			lock_guard<recursive_mutex> lock(_lock);
			for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
			{
				vector<NetworkConnection> tcpconnections = _os.GetNetworkConnections(*it, TCP);
				for(vector<NetworkConnection>::iterator it2 = tcpconnections.begin() ; it2 != tcpconnections.end(); ++it2)
				{
					if((*it2) == *con)
					{
						return (*it);
					}
				}
			}
		}

		UpdateList();

		{
			lock_guard<recursive_mutex> lock(_lock);
			for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
			{
				vector<NetworkConnection> tcpconnections = _os.GetNetworkConnections(*it, TCP);
				for(vector<NetworkConnection>::iterator it2 = tcpconnections.begin() ; it2 != tcpconnections.end(); ++it2)
				{
					if((*it2) == (*con))
					{
						return (*it);
					}
				}
			}
		}

		throw runtime_error("could not find process");
	}

	const vmi_pid_t ProcessCache::FindParentProcessPidByPid(const int pid, const int mainpid)
	{
		vmi_pid_t ret = -1;
		vmi_pid_t* tmp = new vmi_pid_t[2];
		tmp[0] = -1;
		tmp[1] = -1;

		FindParentProcessByPid(pid, tmp, mainpid);
		ret = tmp[0];

		if(ret == 0 || ret == 1 || ret == -1)
		{
			UpdateList();
			FindParentProcessByPid(pid, tmp, mainpid);
		}

		ret = tmp[0];
		delete[] tmp;

		return ret;	
	}

	void ProcessCache::FindParentProcessByPid(const vmi_pid_t pid, vmi_pid_t* tmp, const int parent_pid)
	{
		lock_guard<recursive_mutex> lock(_lock);
		for(vector<Process>::iterator it = _processes.begin() ; it != _processes.end(); ++it)
		{
			if((*it).GetPid() == pid)
			{
				tmp[0] = pid;
				tmp[1] = (*it).GetParentPid();

				while(tmp[1] != 0 && tmp[1] != parent_pid)
				{
					FindParentProcessByPid(tmp[1], tmp, parent_pid);
				}
				break;
			}
		}
	}
}

