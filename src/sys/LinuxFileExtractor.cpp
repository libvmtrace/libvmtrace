
#include <sys/LinuxFileExtractor.hpp>
#include <sys/LinuxVM.hpp>

#define READ_SHARED_MEM(member) [&] () { \
	const auto vmi = sm->Lock(); \
	if (vmi_read_va(vmi, static_cast<addr_t>(static_cast<uintptr_t>(base) + offsetof(shared_memory, member)), pid, sizeof(shared_memory().member), \
				reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&mem) + offsetof(shared_memory, member)), nullptr) == VMI_FAILURE) \
		throw std::runtime_error("Failed to read shared memory region."); \
	sm->Unlock(); \
	return mem.member; \
} ()

#define READ_EXCHANGE_BUF() { \
	const auto vmi = sm->Lock(); \
	if (vmi_read_va(vmi, static_cast<addr_t>(mem.buffer), pid, mem.buffer_size, \
				reinterpret_cast<void*>(exchange_buffer), nullptr) == VMI_FAILURE) \
		throw std::runtime_error("Failed to read exchange buffer."); \
	sm->Unlock(); \
}

#define WRITE_SHARED_MEM(member) { \
	const auto vmi = sm->Lock(); \
	if (vmi_write_va(vmi, static_cast<addr_t>(static_cast<uintptr_t>(base) + offsetof(shared_memory, member)), pid, sizeof(shared_memory().member), \
				reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&mem) + offsetof(shared_memory, member)), nullptr) == VMI_FAILURE) \
		throw std::runtime_error("Failed to write shared memory region."); \
	sm->Unlock(); \
}

#define WRITE_EXCHANGE_BUF() { \
	const auto vmi = sm->Lock(); \
	if (vmi_write_va(vmi, static_cast<addr_t>(mem.buffer), pid, mem.buffer_size, \
				reinterpret_cast<void*>(exchange_buffer), nullptr) == VMI_FAILURE) \
		throw std::runtime_error("Failed to write exchange buffer."); \
	sm->Unlock(); \
}

namespace libvmtrace
{
namespace file_extraction
{
	// constructor of the file extraction class.
	LinuxFileExtractor::LinuxFileExtractor(const std::shared_ptr<SystemMonitor> sm, const std::shared_ptr<LinuxVM> vm,
			const Process process, const std::string agent_path, const bool skip_tree)
		: sm(sm), vm(vm), base(0), process(process), pid(process.GetPid())
	{
		base = vm->GetSymbolAddrVa(agent_path, process, "mem", false);

		if (READ_SHARED_MEM(magic) != magic_value)
			throw std::runtime_error("Invalid magic value.");
		
		while (READ_SHARED_MEM(buffer) == 0)
			std::this_thread::sleep_for(sleep_interval);

		if (skip_tree)
			set_flag(file_extraction::status::skip_tree);

		set_flag(file_extraction::status::endian_match);
		if (!skip_tree && !wait_for_flag(file_extraction::status::transmitting_file_tree))
			throw std::runtime_error("Failed when creating in-guest file tree.");

		exchange_buffer = (uintptr_t) malloc(READ_SHARED_MEM(buffer_size));
	}

	// destructor of the file extracion class.
	LinuxFileExtractor::~LinuxFileExtractor()
	{
		if (exchange_buffer)
			free((void*) exchange_buffer);
	}

	// opens a handle to write the current file into, must be called before read_chunk is invoked.
	void LinuxFileExtractor::open_file(const std::string& filename)
	{
		assert(!file.is_open());
		file = std::ofstream(filename, std::ofstream::binary);

		if (file.fail())
			throw std::runtime_error("Failed to open file.");
		
		crc = { };
		exp_crc = 0xFFFFFFFF;
	}

	// closes the file handle in case we want to transfer multiple files.
	void LinuxFileExtractor::close_file()
	{
		assert(file.is_open());
		file.close();
		crc = { };
		exp_crc = 0xFFFFFFFF;
	}

	// request a file to be transmitted, may only be called after the file tree has already been exchanged.
	void LinuxFileExtractor::request_file(const std::string& filename)
	{
		assert(!file.is_open());
		
		if (READ_SHARED_MEM(status) & to_underlying(file_extraction::status::file_selected))
			throw std::runtime_error("File to extract was already selected.");

		// write filename and size to buffer.
		memset((char*) exchange_buffer, 0, mem.buffer_size);
		filename.copy((char*) exchange_buffer, mem.buffer_size);
		mem.transmission_size = filename.length();
		WRITE_SHARED_MEM(transmission_size);
		WRITE_EXCHANGE_BUF();

		// notify in-guest agent about selection.
		set_flag(file_extraction::status::file_selected);
	}

	// core logic for transmitting a file, reads one memory mapped chunk of the file.
	// returns true, if this chunk was the last of the current file. 
	bool LinuxFileExtractor::read_chunk(float* const progress)
	{
		if (!file.is_open())
			throw std::runtime_error("Invalid state, open a file first.");

		// pull until the agent becomes ready to transmit.
		if (!wait_for_flag(file_extraction::status::ready_signal))
			throw std::runtime_error("Agent failed to extract file.");

		// sender should be ready now.
		assert(mem.status & to_underlying(file_extraction::status::ready_signal));

		// synchronize buffer and calculate position in transmission.
		READ_EXCHANGE_BUF();
		READ_SHARED_MEM(transmission_size);
		assert(mem.transmission_size > 0);
		const auto remaining = mem.transmission_size - file.tellp();
		const auto to_read = std::min(remaining, static_cast<uint64_t>(mem.buffer_size));

		// write chunk to file and compute next part of crc.
		file.write((char*) exchange_buffer, to_read);
		exp_crc = crc.update((void*) exchange_buffer, to_read);

		// was this the last chunk?
		const auto last = static_cast<uint64_t>(file.tellp()) >= mem.transmission_size;

		// read crc before finishing.
		if (last)
			READ_SHARED_MEM(crc);

		// reset ready signal.
		mem.status &= ~to_underlying(file_extraction::status::ready_signal);
		WRITE_SHARED_MEM(status);

		// calculate progress.
		if (progress)
			*progress = file.tellp() / static_cast<float>(mem.transmission_size);
		
		// was this the last chunk?
		return last;
	}

	// check if the file was transfered correctly.
	bool LinuxFileExtractor::check_crc()
	{
		return exp_crc == mem.crc;
	}

	// enable a single flag.
	void LinuxFileExtractor::set_flag(const file_extraction::status s)
	{
		assert(s != file_extraction::status::error_abort);
		mem.status = READ_SHARED_MEM(status) | to_underlying(s);
		WRITE_SHARED_MEM(status);
	}

	// synchronize with the agent, block until a flag is met.
	bool LinuxFileExtractor::wait_for_flag(const file_extraction::status s)
	{
		assert(s != file_extraction::status::error_abort);

		do
		{
			if (!!(READ_SHARED_MEM(status) & to_underlying(s)))
				return true;
			
			std::this_thread::sleep_for(sleep_interval);
		} while (!(mem.status & to_underlying(status::error_abort)));

		return false;
	}
}
}

#undef READ_SHARED_MEM
#undef READ_EXCHANGE_BUF
#undef WRITE_SHARED_MEM
#undef WRITE_EXCHANGE_BUF

