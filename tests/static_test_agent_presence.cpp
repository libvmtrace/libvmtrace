
#include <libvmi/libvmi.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

using namespace libvmtrace;

int main(int argc, char* argv[]) 
{
	std::cout << "--- Linux File Extraction Agent ---" << std::endl;
	ElfHelper elf;
	const auto is_elf = elf.elf_check_file((Elf64_Ehdr*) linux_agent_start);
	std::cout << "Size: 0x" << std::hex << uintptr_t(linux_agent_end) - uintptr_t(linux_agent_start)
		<< " - ELF Magic: " << (is_elf ? "OK" : "FAIL") << std::endl;
	if (is_elf)
	{
		const auto symbol = elf.elf_get_symbol_addr(linux_agent_start, ".symtab", "mem", false);
		if (symbol)
			std::cout << "Located export in agent at: 0x" << std::hex << uintptr_t(symbol) << std::endl;
		else
			std::cerr << "Failed to locate export in agent." << std::endl;
	}
	
	return 0;
}
