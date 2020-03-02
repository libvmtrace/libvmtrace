
#include <libvmtrace.hpp> 
#include <sys/LinuxVM.hpp>
#include <sys/LinuxELFInjector.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <cassert>
#include <algorithm>
#include <optional>

using namespace libvmtrace;

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

// TODO: look for a process to inject code into here.
std::optional<Process> find_suitable_process(const vmi_pid_t pid)
{
	const auto plist = vm->GetProcessList();
	const auto result = std::find_if(plist.begin(), plist.end(),
			[&](const auto& p) -> bool { return p.GetPid() == pid; });
	
	if (result == plist.end())
		return std::nullopt;

	return *result;
}

// main routine of the shared library / executable.
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
	if (argc < 4)
	{
		std::cerr << "USAGE: " << argv[0] << " [VM_NAME] [PID] [EXEC]" << std::endl;
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

		std::cout << "Found process: " << process->GetName() << std::endl;

		std::ifstream file(std::string("./").append(argv[3]), std::ios::binary);
		const auto exe = std::make_shared<std::vector<uint8_t>>(
				std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

		LinuxELFInjector inj(sm, vm, *process);
		const auto child = inj.inject_executable(exe);
		std::cout << "Forked child: " << std::dec << child.GetPid() << std::endl;
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

