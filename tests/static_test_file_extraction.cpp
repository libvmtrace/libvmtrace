
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
std::unique_ptr<LinuxFileExtractor> extractor;

// shutdown routine.
void shutdown(int sig)
{
	extractor = nullptr;
	vm = nullptr;
	sm = nullptr;

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

	// initialize vmtrace and delegate.
	try
	{
		vm = std::make_unique<LinuxVM>(sm);
		std::cout << "Successfully initiated VMI on " << argv[1] << "!" << std::endl;

		const auto process = find_suitable_process(static_cast<vmi_pid_t>(std::stoi(argv[2])));
		if (!process.has_value())
			throw std::runtime_error("Failed to retrieve suitable process from VM.");

		// inject the agent and create extract helper.
		std::vector<uint8_t> agent;
		agent.assign(linux_agent_start, linux_agent_end);
		const auto child = vm->InjectELF(*process, agent);
		const auto should_skip = true;
		extractor = std::make_unique<LinuxFileExtractor>(sm, vm, child, agent, should_skip);
		
		// helper lambda to wrap extraction and status indicator of file download.
		const auto read_file = [](const std::string& name)
		{
			std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
			extractor->open_file(name);
			
			float progress{};
			while (true)
			{
				const auto finished = extractor->read_chunk(&progress);
				const auto sym = static_cast<int32_t>(progress * 60);
				const auto lhs = std::string(sym, '=');
				const auto rhs = std::string(60 - sym, ' ');

				std::cout << "\r" << "File: " << name << " [" << lhs << ">" << rhs << "] "
					<< std::dec << static_cast<int32_t>(progress * 100.f) << "%";

				if (finished)
					break;
			}

			std::cout << std::endl;

			if (!extractor->check_crc())
				std::cout << "File corrupted, invalid CRC." << std::endl;

			extractor->close_file();
			std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
			std::cout << "Transmission duration: "
				<< std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()
				<< " ms" << std::endl;
		};

		// read the file system tree from the in-guest agent.
		if (!should_skip)
		{
			read_file("./tree");
			std::cout << "File tree exchanged, please make your choice." << std::endl;
		}

		// request file to extract.
		std::cout << "Select target file: ";
		std::string selection;
		std::cin >> selection;
		extractor->request_file(selection);

		// extract target file.
		read_file("./file");
		std::cout << "File successfully extracted." << std::endl;
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


