
#include <sys/FileExtraction.hpp>
#include <agent/LinuxAgentUtil.hpp>
#include <util/Crc32.hpp>
#include <iostream>
#include <fstream>
#include <ext/stdio_filebuf.h>
#include <thread>
#include <cassert>
#include <algorithm>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

using namespace libvmtrace::file_extraction;
using namespace libvmtrace::util;
using namespace linux_agent;

// will produce a warning, but in this case we want it to be default initialized at compile time.
extern shared_memory mem{};

// poor man's condition variable.
// returns true, if the status has flipped and no error occured.
bool wait_for_flag(status s, bool value)
{
	assert(s != status::error_abort);

	do
	{
		if (!!(mem.status & to_underlying(s)) == value)
			return true;

		std::this_thread::sleep_for(sleep_interval);
	} while (!(mem.status & to_underlying(status::error_abort)));

	return false;
}

// wait for flag and perform error handling.
#define AWAIT_FLAG(s) if (!wait_for_flag(s, true)) \
{ \
	std::cerr << "Error occured when waiting for flag at " << __LINE__ << "." << std::endl; \
	return 1; \
}

// end transmission due to error and let the host know about the failure.
#define FAIL() \
{ \
	std::cerr << "Error occured when performing transmission at " << __LINE__ << "." << std::endl; \
	mem.status |= to_underlying(status::error_abort); \
	if (mem.buffer) \
	{ \
		munlock((void*) mem.buffer, mem.buffer_size); \
		free((void*) mem.buffer); \
	} \
	return 1; \
}

// read a given stream to the transmission buffer, chunk by chunk.
// returns true after successful transmission, false otherwise.
bool read_stream_to_buffer(std::istream&& i)
{
	if (i.fail())
		return false;

	i.ignore(std::numeric_limits<std::streamsize>::max());
	mem.transmission_size = i.gcount();
	i.clear();
	i.seekg(0, std::ios_base::beg);

	auto remaining = mem.transmission_size;
	Crc32 crc;

	// compute checksum first.
	while (remaining > 0)
	{
		const auto to_read = std::min(remaining, static_cast<uint64_t>(mem.buffer_size));
		remaining -= to_read;

		if (!i.read((char*) mem.buffer, to_read))
			return false;

		mem.crc = crc.update((void*) mem.buffer, to_read);
	}

	// roll back to the beginning.
	remaining = mem.transmission_size;
	i.clear();
	i.seekg(0, std::ios_base::beg);
	
	// start transmission now.
	while (remaining > 0)
	{
		const auto to_read = std::min(remaining, static_cast<uint64_t>(mem.buffer_size));
		remaining -= to_read;

		if (!i.read((char*) mem.buffer, to_read))
			return false;

		mem.status |= to_underlying(status::ready_signal);	
	
		if (!wait_for_flag(status::ready_signal, false))
			return false;
	}

	// there should be even amounts of flip/flops at this point.
	assert(!(mem.status & to_underlying(status::ready_signal)));

	// clear out transmission size.
	mem.transmission_size = 0;	

	// successful transmission.
	return true;
}

// main routine of the shared library / executable.
int main()
{
	// print debug information.
	std::cout << "Shared memory at: " << std::hex << &mem <<
		" [" << std::dec << getpid() << "]" << std::endl;

	// allocate memory and lock into virutal memory.
	mem.buffer_size = default_size;
	mem.buffer = (uintptr_t) malloc(mem.buffer_size);
	mlock((void*) mem.buffer, mem.buffer_size);

	// wait for the host system to acknowledge our endianness.
	std::cout << "Waiting for endianness acknowledge." << std::endl;
	AWAIT_FLAG(status::endian_match);
	std::cout << "Acknowledged endianness, transmitting file tree..." << std::endl;

	// notify about incoming file tree and start transmission.
	if (!(mem.status & to_underlying(status::skip_tree)))
	{
		// create file system tree in a temporary, memory mapped file.
		temporary_file file("/fs_extract_tree");

		// pipe tree to temp file.
		const auto current = dup(STDOUT_FILENO);
		dup2(file.get_descriptor(), STDOUT_FILENO);
		system("tree /");
		dup2(current, STDOUT_FILENO);
		lseek(file.get_descriptor(), 0, SEEK_SET);

		// signal file tree transmission.
		status_guard guard(mem, status::transmitting_file_tree);
		
		// finally transmit the file tree in chunks.
		__gnu_cxx::stdio_filebuf<char> buf(file.get_descriptor(), std::ios::in);
		if (!read_stream_to_buffer(std::istream(&buf)))
			FAIL();
	} 

	// finished transmission of file system tree.
	std::cout << "Transmitted file system tree, awaiting selection." << std::endl;

	// wait for a file to be selected, result will be in the transmission buffer.
	AWAIT_FLAG(status::file_selected);

	// transmission should be in initial state.
	assert(!(mem.status & to_underlying(status::ready_signal)));

	// read name from the transmission buffer. we assume the written string is null-terminated at this point,
	// at worst we read till the end of the buffer, get an invalid file name and abort here.
	std::string target((const char*) mem.buffer, std::min(static_cast<uint32_t>(mem.transmission_size), mem.buffer_size));
	if (!read_stream_to_buffer(std::ifstream(target, std::ifstream::binary)))
		FAIL();
		
	// assume no error has occured.
	assert(!(mem.status & to_underlying(status::error_abort)));	
	
	// transmission successful, terminate now.
	std::cout << "Transmission successfully completed." << std::endl;
	munlock((void*) mem.buffer, mem.buffer_size);
	free((void*) mem.buffer);
	return 0;
}

#undef AWAIT_FLAG
#undef FAIL

