
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

using namespace libvmtrace;

bool check_elf(uint8_t* start, uint8_t* end)
{
	const uint8_t elf_magic[] = { 0x7F, 0x45, 0x4C, 0x46 };
	const auto diff = uintptr_t(end) - uintptr_t(start);

	if (diff < 4)
		return false;

	for (auto i = 0; i < sizeof(elf_magic); i++)
		if (elf_magic[i] != start[i])
			return false;

	return true;
}

int main(int argc, char* argv[]) 
{
	std::cout << "--- Linux File Extraction Agent ---" << std::endl;
	std::cout << "Size: 0x" << std::hex << uintptr_t(linux_agent_end) - uintptr_t(linux_agent_start)
		<< " - ELF Magic: " << (check_elf(linux_agent_start, linux_agent_end) ?
				"OK" : "FAIL") << std::endl;
	return 0;
}
