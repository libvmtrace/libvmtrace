
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>
#include <sys/LinuxFileExtractor.hpp>
#include <optional>
#include <chrono>

using namespace libvmtrace;
using namespace libvmtrace::file_extraction;

// vmtrace wrapper.
std::shared_ptr<SystemMonitor> sm;
std::shared_ptr<LinuxVM> vm;
std::unique_ptr<Int3> bpm;
std::unique_ptr<RegisterMechanism> rm;

// shutdown routine.
void shutdown(int sig)
{
	if (vm)
		vm->Stop();

	if (sm)
		sm->Stop();

	sm = nullptr;
	bpm = nullptr;
	rm = nullptr;
	vm = nullptr;

	exit(sig);
}

std::optional<Process> find_suitable_process(const vmi_pid_t pid)
{
	const auto plist = vm->GetProcessList();
	const auto result = std::find_if(plist.begin(), plist.end(),
			[&](const auto& p) -> bool { return p.GetPid() == pid; });
	
	if (result == plist.end())
		return std::nullopt;

	return *result;
}

int main(int argc, char** argv)
{
	// set up event handlers.
	struct sigaction act;
	act.sa_handler = shutdown;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, nullptr);
	sigaction(SIGTERM, &act, nullptr);
	sigaction(SIGINT, &act, nullptr);
	sigaction(SIGALRM, &act, nullptr);
	sigaction(SIGPIPE, &act, nullptr);
	sigaction(SIGSEGV, &act, nullptr);

	// print usage.
	if (argc < 3)
	{
		std::cerr << "USAGE: " << argv[0] << " [VM_NAME] [PID]" << std::endl;
		return 1;
	}

	// create vmtrace wrapper objects.
	sm = std::make_shared<SystemMonitor>(argv[1], true);
	bpm = std::make_unique<Int3>(*sm);
	rm = std::make_unique<RegisterMechanism>(*sm);
	sm->SetBPM(bpm.get(), bpm->GetType());
	sm->SetRM(rm.get());

	// initialize vmtrace and delegate.
	try
	{
		sm->Init();
		bpm->Init();
		rm->Init();
		sm->Loop();
		vm = std::make_unique<LinuxVM>(sm.get());
		std::cout << "Successfully initiated VMI on " << argv[1] << "!" << std::endl;

		const auto process = find_suitable_process(static_cast<vmi_pid_t>(std::stoi(argv[2])));
		if (!process.has_value())
			throw std::runtime_error("Failed to retrieve suitable process from VM.");


		//std::cout << "Select target file: ";
		std::string selection = "/home/guest/files/small";
		//std::cin >> selection;
		
		vm->ExtractFile(*process, selection, "./file");
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		sm->Unlock();
	}
	catch (...)
	{
		std::cerr << "Unknown error occured." << std::endl;
	}
	
	// clear up resources.
	shutdown(0);
	return 0;
}


