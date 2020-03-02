
#pragma once

#include <libvmtrace.hpp>

namespace libvmtrace
{
namespace util
{
	class LockGuard
	{
	public:
		LockGuard(std::shared_ptr<SystemMonitor> monitor) : monitor(monitor)
		{
			inst = monitor->Lock();
		}

		~LockGuard()
		{
			monitor->Unlock();
		}

		LockGuard(LockGuard const& other) = delete;
		LockGuard& operator=(LockGuard const& other) = delete;
		LockGuard(LockGuard&& other) = delete;
		LockGuard& operator=(LockGuard&& other) = delete;
	
		vmi_instance_t get() const
		{
			return inst;
		}

	private:
		std::shared_ptr<SystemMonitor> monitor;
		vmi_instance_t inst;
	};
}
}

