
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ElfHelper.hpp>
#include <elf.h>
#include <glib.h>
#include <unistd.h>
#include <stdlib.h>

namespace libvmtrace
{
	int ElfHelper::elf_check_file(Elf64_Ehdr* hdr) 
	{
		if(!hdr)
		{
			return 0;
		}
		if(hdr->e_ident[EI_MAG0] != ELFMAG0) 
		{
			return 0;
		}
		if(hdr->e_ident[EI_MAG1] != ELFMAG1) 
		{
			return 0;
		}
		if(hdr->e_ident[EI_MAG2] != ELFMAG2) 
		{
			return 0;
		}
		if(hdr->e_ident[EI_MAG3] != ELFMAG3) 
		{
			return 0;
		}
		return 1;
	}

	size_t ElfHelper::get_section_offset(void* memory, const char* section)
	{
		unsigned int i=0;
		Elf64_Ehdr* ehdr = (Elf64_Ehdr*)memory;
		Elf64_Shdr* sect = (Elf64_Shdr*)((char*)memory + ehdr->e_shoff);
		char* string_table = (char*)memory+ (sect[ehdr->e_shstrndx].sh_offset);

		if (!elf_check_file(ehdr))
		{
			return 0;
		}

		for(i=0; i<ehdr->e_shnum; i++)
		{
			char *sec_name = string_table+sect[i].sh_name;

			if(!strcmp(sec_name, section))
			{
				return sect[i].sh_offset;
			}
		}

		return 0;
	}

	addr_t ElfHelper::elf_get_symbol_addr(void* memory, const char* section, const char* symbol, const bool only_functions) 
	{
		unsigned int i=0;
		Elf64_Ehdr* ehdr = (Elf64_Ehdr*)memory;
		Elf64_Shdr* sect = (Elf64_Shdr*)((char*)memory + ehdr->e_shoff);
		char* string_table = (char*)memory+ (sect[ehdr->e_shstrndx].sh_offset);

		if (!elf_check_file(ehdr))
			return 0;
		
		for(i=0; i<ehdr->e_shnum; i++)
		{
			char *sec_name = string_table+sect[i].sh_name;
			char* dynstr_table = (char*)memory + (sect[sect[i].sh_link].sh_offset);
			char *sname = NULL;

			if(!strcmp(sec_name, section) && sect[i].sh_entsize > 0)
			{
				unsigned int symit = 0;
				unsigned int count = (int) sect[i].sh_size/sect[i].sh_entsize;

				Elf64_Sym* s = (Elf64_Sym*) ((char*)memory + sect[i].sh_offset);
				for(symit=0; symit<count; symit++)
				{
					if (only_functions && !((ELF32_ST_BIND(STB_GLOBAL) | ELF64_ST_TYPE(STT_FUNC)) & s[symit].st_info))
						continue;
					if (s[symit].st_value == 0)
						continue;
					
					sname = dynstr_table + s[symit].st_name;

					if (strcmp(symbol, sname) == 0)
					{
						return s[symit].st_value;
					}

				}
			}
		}
		return 0;
	}

	char* ElfHelper::map_file(const char* file_name, off_t offset, int* len)
	{
		char *addr;
		int fd;
		struct stat sb;
		off_t  pa_offset;
		size_t length;

		fd = open(file_name, O_RDONLY);
		if (fd == -1)
			return NULL;

		if (fstat(fd, &sb) == -1)           /* To obtain file size */
			return NULL;

		pa_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
		/* offset for mmap() must be page aligned */

		if (offset >= sb.st_size) 
		{
			fprintf(stderr, "offset is past end of file\n");
			return NULL;
		}

		length = sb.st_size - offset;
		addr = (char *)mmap(NULL, (length + offset - pa_offset), PROT_READ,MAP_PRIVATE, fd, pa_offset);
		if (addr == MAP_FAILED)
			return NULL;

		*len = length;

		return addr;
	}
}

