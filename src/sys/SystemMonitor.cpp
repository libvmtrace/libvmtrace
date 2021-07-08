
#include <sys/SystemMonitor.hpp>
#include <sys/BreakpointMechanism.hpp>
#include <sys/RegisterMechanism.hpp>

namespace libvmtrace
{
	using namespace std::chrono_literals;

	SystemMonitor::SystemMonitor(const std::string name, const bool event_support, const bool ept_support) noexcept(false) :
		name(name), event_support(event_support), worker(nullptr), profile(""), ept_support(ept_support)
	{
		// dirty trick to prevent shared_from_this from throwing a bad weak ptr.
		// does this break anything?
		const auto unused = std::shared_ptr<SystemMonitor>(this, [](SystemMonitor*){});
		
		uint64_t init_flags = VMI_INIT_DOMAINNAME;

		if (event_support)
			init_flags = VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS;

		if (vmi_init_complete(&vmi, (void*) name.c_str(), init_flags, nullptr,
					VMI_CONFIG_GLOBAL_FILE_ENTRY, nullptr, nullptr) == VMI_FAILURE)
			throw std::runtime_error("Failed to init VMI.");

		if (vmi_pause_vm(vmi) != VMI_SUCCESS)
			throw std::runtime_error("Failed to pause VM.");

		rm = std::make_shared<RegisterMechanism>(shared_from_this());
		
		if (ept_support)
			inj = std::make_shared<ExtendedInjectionStrategy>(
					std::shared_ptr<SystemMonitor>(std::shared_ptr<SystemMonitor>{}, this));
		else
			inj = std::make_shared<PrimitiveInjectionStrategy>(
					std::shared_ptr<SystemMonitor>(std::shared_ptr<SystemMonitor>{}, this));

		bpm = std::make_shared<BreakpointMechanism>(shared_from_this());

		if (event_support)
			worker = std::make_shared<std::thread>(&SystemMonitor::ProcessEvents, this); 

		if (vmi_resume_vm(vmi) != VMI_SUCCESS)
			throw std::runtime_error("Failed to resume VM.");
	}

	SystemMonitor::~SystemMonitor() noexcept(false)
	{
		if (vmi_pause_vm(vmi) != VMI_SUCCESS)
			throw std::runtime_error("Failed to pause VM.");
		
		bpm = nullptr;
		inj = nullptr;
		rm = nullptr;

		if (worker)
		{
			worker_exit.set_value();
			worker->join();
			worker = nullptr;
		}

		if (vmi_resume_vm(vmi) != VMI_SUCCESS)
			throw std::runtime_error("Failed to resume VM.");

		vmi_destroy(vmi);
	}

	vmi_instance_t SystemMonitor::Lock()
	{
		vmi_mtx.lock();
		return vmi;
	}

	void SystemMonitor::Unlock()
	{
		vmi_mtx.unlock();
	}

	void SystemMonitor::ProcessEvents()
	{
		const auto future = worker_exit.get_future();
		while (future.wait_for(std::chrono::seconds(0)) == std::future_status::timeout)
		{
			vmi_mtx.lock();
			if (vmi_events_listen(vmi, 0) != VMI_SUCCESS)
				std::cerr << "Error waiting for events, quitting..." << std::endl;
			rm->FinalizeEvents();
			vmi_mtx.unlock();
		}
	}
}

