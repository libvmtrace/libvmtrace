
#ifndef __ELFHELPER_H__
#define __ELFHELPER_H__

#include <libelf.h>
#include <libvmi/libvmi.h>
#include <glib.h>

namespace libvmtrace
{
	class ElfHelper 
	{
	public:
		ElfHelper() = default;
		int elf_check_file(Elf64_Ehdr* hdr);
		addr_t elf_get_symbol_addr(void* memory, const char* section,const char* symbol);
		size_t get_section_offset(void* memory, const char* section);
		char* map_file(const char* file_name, off_t offset, int*);
	};
}

#endif

