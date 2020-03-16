
#pragma once

#include <libvmtrace.hpp>
#include <sys/FileExtraction.hpp>
#include <util/Crc32.hpp>
#include <fstream>

namespace libvmtrace
{
namespace file_extraction
{
	class LinuxFileExtractor
	{
	public:
		LinuxFileExtractor(std::shared_ptr<SystemMonitor> sm, std::shared_ptr<LinuxVM> vm,
				Process process, const std::string agent_path, const bool skip_tree = true);
		LinuxFileExtractor(std::shared_ptr<SystemMonitor> sm, std::shared_ptr<LinuxVM> vm,
				Process process, std::vector<uint8_t>& agent, const bool skip_tree = true);
		virtual ~LinuxFileExtractor();

		LinuxFileExtractor(LinuxFileExtractor const& other) = delete;
		LinuxFileExtractor& operator=(LinuxFileExtractor const& other) = delete;
		LinuxFileExtractor(LinuxFileExtractor&& other) = delete;
		LinuxFileExtractor& operator=(LinuxFileExtractor&& other) = delete;

		void open_file(const std::string& filename);
		void close_file();
		void request_file(const std::string& filename);
		bool read_chunk(float* const progress = nullptr);
		bool check_crc();

	private:
		void initialize(const bool skip_tree);
		void set_flag(status s);
		bool wait_for_flag(status s);	

		std::shared_ptr<SystemMonitor> sm;
		std::shared_ptr<LinuxVM> vm;
		addr_t base;
		Process process;
		vmi_pid_t pid;

		shared_memory mem;
		uintptr_t exchange_buffer;
		std::ofstream file;
		util::Crc32 crc;
		uint32_t exp_crc = 0xFFFFFFFF;
	};
}
}

