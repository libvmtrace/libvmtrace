
#include <sys/SystemMonitor.hpp>

using namespace std;

namespace libvmtrace
{
	static int stop_now = 0;

	SystemMonitor::~SystemMonitor()
	{
		if (worker)
		{
			worker->join();
		}
		
		stop_now = 1;
		
		if(_bpm_type == DRAKVUF)
		{
			// drakvuf_close(_drakvuf, false);
		}
		else if(_bpm_type == INTTHREE || _bpm_type == ALTP2M)
		{
			vmi_destroy(_vmi);
		}
	}

	status_t SystemMonitor::Init()
	{
		if(_bpm == nullptr)
		{
			throw runtime_error("Please attach a breakpoint manager");
		}

		if(_bpm_type == DRAKVUF)
		{
			if(!_event_support)
			{
				throw runtime_error("Event need to be supported");
			}
			else if(_profile == "")
			{
				throw runtime_error("Unknown profile");
			}
			else
			{
				try
				{
					// drakvuf_init(&_drakvuf, _name.c_str(), _profile.c_str(), false, false);
					_initialized = true;
					return VMI_SUCCESS;
				}
				catch(int e)
				{
					throw runtime_error("Failed to initialized Drakvuf");

					return VMI_FAILURE;
				}
			}

			return VMI_FAILURE;
		}
		else if(_bpm_type == INTTHREE || _bpm_type == ALTP2M)
		{
			uint64_t init_flags = VMI_INIT_DOMAINNAME;
		
			if(_event_support)
			{
				init_flags = VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS;
				_event_support = true;
			}

			if(!_initialized)
			{
				if (vmi_init_complete(&_vmi, (void*)_name.c_str(),init_flags, NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) == VMI_FAILURE) 
				{
					throw runtime_error("Failed to init VMI");
					return VMI_FAILURE;
				}
				else
				{
					_initialized = true;
					return VMI_SUCCESS;
				}
			}
			else
			{
				return VMI_FAILURE;
			}
		}
		else
		{
			throw runtime_error("Unknown BPM");
			return VMI_FAILURE;
		}
	}

	void SystemMonitor::DeInit()
	{
		//vmi_destroy(_vmi);
	}

	vmi_instance_t SystemMonitor::Lock()
	{
		// cout << "LOCK" << endl;
		_vmi_mtx.lock();
		
		// if(_bpm_type == DRAKVUF)
		// {
		// 	if (_is_locked == 0)
		// 	{
		// 		_vmi = drakvuf_lock_and_get_vmi(_drakvuf);
		// 	}
		// 	_is_locked++;
		// }
		
		return _vmi;
	}

	void SystemMonitor::Unlock()
	{
		// cout << "UNLOCK" << endl;
		// if(_bpm_type == DRAKVUF)
		// {
		// 	_is_locked--;
		// 	if (_is_locked == 0)
		// 	{
		// 		drakvuf_release_vmi(_drakvuf);
		// 	}
		// }
		
		_vmi_mtx.unlock();	
	}

	static void process_events(vmi_instance_t vmi) 
	{
		status_t status;
		while(stop_now == 0) 
		{
			status = vmi_events_listen(vmi, 500);
			if (status != VMI_SUCCESS) 
			{
				cerr << "Error waiting for events, quitting...\n" << endl;
			}
		}
	}

	void SystemMonitor::Loop(void)
	{
		if(_bpm_type == DRAKVUF)
		{
			// worker = new thread(drakvuf_loop, _drakvuf);
		}
		else if(_bpm_type == INTTHREE || _bpm_type == ALTP2M)
		{
			worker = new thread(process_events, _vmi); 
		}
	}

	void SystemMonitor::Stop(void)
	{
		stop_now = 1;

		// if(_bpm_type == DRAKVUF)
		// {
		// 	drakvuf_interrupt(_drakvuf, 1);
		// }
	}
}

