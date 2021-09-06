
#include <sys/SystemMonitor.hpp>
#include <sys/BreakpointMechanism.hpp>
#include <sys/RegisterMechanism.hpp>

namespace libvmtrace
{
	using namespace std::chrono_literals;

	SystemMonitor::SystemMonitor(const std::string name, const bool event_support, const bool ept_support, const char* socketPath) noexcept(false) :
		name(name), event_support(event_support), worker(nullptr), profile(""), ept_support(ept_support)
	{
		// dirty trick to prevent shared_from_this from throwing a bad weak ptr.
		// does this break anything?
		const auto unused = std::shared_ptr<SystemMonitor>(this, [](SystemMonitor*){});
		
		uint64_t init_flags = VMI_INIT_DOMAINNAME;

		if (event_support)
			init_flags = VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS;

		vmi_init_data_t *init_data = NULL;
#ifdef ENABLE_KVMI
		if(socketPath != nullptr) {
			init_data = (vmi_init_data_t*)malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
			init_data->count = 1;
			init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
			init_data->entry[0].data = strdup(socketPath);
		}
		else {
			throw std::runtime_error("KVMI requires socket path");
		}
#endif // ENABLE_KVMI
		if (vmi_init_complete(&vmi, (void*) name.c_str(), init_flags, init_data,
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
			//vmi_mtx.unlock();
			worker->join();
			//vmi_mtx.lock();
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
			if (rm)
				rm->FinalizeEvents();
			vmi_mtx.unlock();
		}
	}
}

