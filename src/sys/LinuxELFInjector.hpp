
#pragma once

#include "libvmtrace.hpp"
#include <atomic>
#include <optional>

namespace libvmtrace
{
	class LinuxELFInjector
	{
		// TODO: the shellcode below can be optimized,
		// because the linux kernel perserves registers
		// for syscalls even when not specified
		// by the SystemV x86_64 ABI.
		const struct
		{
			/*
			 * s: .quad 0xDEADBEEF
			 * name: .ascii "file_extraction"
			 * empty: .ascii "\0"
			 *
			 * mov rax, 319				# memfd_create
			 * lea rdi, [rip + name]		# name is only used to debug.
			 * mov rsi, 1				# MFD_CLOEXEC
			 * syscall
			 * mov r12, rax				# store file descriptor.
			 * mov rdi, r12
			 * mov rax, 77				# ftruncate
			 * mov rsi, [rip + s]
			 * syscall
			 * mov rax, 9				# mmap
			 * xor rdi, rdi
			 * mov rsi, [rip + s]
			 * mov rdx, 3				# PROT_READ | PROT_WRITE
			 * mov r10, 1				# MAP_SHARED
			 * mov r8, r12				# file descriptor
			 * xor r9, r9
			 * syscall
			 * mov r13, rax
			 * mov r11, rax				# start r11 at end of buffer and loop backwards.
			 * add r11, [rip + s]
			 * dec r11
			 * page_loop:				# page in the mapped memory for vmi.
			 * 	mov rax, [r11]
			 * 	sub r11, 0x1000
			 * 	cmp r11, r13
			 * 	jg page_loop
			 * int 3				# interrupt and request the host to map memory.
			 * mov rax, 26				# msync
			 * mov rdi, r13
			 * mov rsi, [rip + s]
			 * mov rdx, 4				# MS_SYNC
			 * syscall
			 * mov rax, 11				# munmap
			 * mov rdi, r13
			 * mov rsi, [rip + s]
			 * syscall
			 * mov rax, 322				# execveat
			 * mov rdi, r12
			 * lea rsi, [rip + empty]		# libc says we don't need a valid path.
			 * xor rdx, rdx
			 * xor r10, r10
			 * mov r8, 0x1000			# AT_EMPTY_PATH
			 * syscall
			 */
			const char* data =  "\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x66\x69\x6C\x65\x5F\x65"
				"\x78\x74\x72\x61\x63\x74\x69\x6F\x6E\x00\x48\xC7\xC0\x3F\x01\x00\x00"
				"\x48\x8D\x3D\xE2\xFF\xFF\xFF\x48\xC7\xC6\x01\x00\x00\x00\x0F\x05\x49"
				"\x89\xC4\x4C\x89\xE7\x48\xC7\xC0\x4D\x00\x00\x00\x48\x8B\x35\xBD\xFF"
				"\xFF\xFF\x0F\x05\x48\xC7\xC0\x09\x00\x00\x00\x48\x31\xFF\x48\x8B\x35"
				"\xAA\xFF\xFF\xFF\x48\xC7\xC2\x03\x00\x00\x00\x49\xC7\xC2\x01\x00\x00"
				"\x00\x4D\x89\xE0\x4D\x31\xC9\x0F\x05\x49\x89\xC5\x49\x89\xC3\x4C\x03"
				"\x1D\x87\xFF\xFF\xFF\x49\xFF\xCB\x49\x8B\x03\x49\x81\xEB\x00\x10\x00"
				"\x00\x4D\x39\xEB\x7F\xF1\xCC\x48\xC7\xC0\x1A\x00\x00\x00\x4C\x89\xEF"
				"\x48\x8B\x35\x63\xFF\xFF\xFF\x48\xC7\xC2\x04\x00\x00\x00\x0F\x05\x48"
				"\xC7\xC0\x0B\x00\x00\x00\x4C\x89\xEF\x48\x8B\x35\x49\xFF\xFF\xFF\x0F"
				"\x05\x48\xC7\xC0\x42\x01\x00\x00\x4C\x89\xE7\x48\x8D\x35\x4D\xFF\xFF"
				"\xFF\x48\x31\xD2\x4D\x31\xD2\x49\xC7\xC0\x00\x10\x00\x00\x0F\x05";
			size_t size = 0xD9;
			size_t displacement = 0x18;
			size_t interrupt_mmap = 0x8B;
		} shellcode{};

		struct
		{
			addr_t thread_struct, sp0, ip;
			uint32_t execveat_index = 322;
		} offsets;
	
		using callback_fn = std::function<bool(const Event*, void*)>;

		class injection_listener : public EventListener
		{
		public:
			injection_listener(LinuxELFInjector& parent, callback_fn fn)
				: parent(parent), fn(fn) { };
			bool callback(const Event* event, void* data) final;

		private:
			LinuxELFInjector& parent;
			callback_fn fn;
		};

	public:
		LinuxELFInjector(std::shared_ptr<SystemMonitor> sm, std::shared_ptr<LinuxVM> vm, Process parent);
		Process inject_executable(std::shared_ptr<std::vector<uint8_t>> executable);

	private:
		bool on_injection(const Event* event, void* data);
		bool on_cr3_change(const Event* event, void* data);
		bool on_mmap_break(const Event* event, void* data);
		bool on_execveat(const Event* event, void* data);
		bool on_last_chance(const Event* event, void* data);

		std::unique_ptr<injection_listener> inject_listener, cr3_listener,
			mmap_listener, execveat_listener, last_chance_listener;

		std::shared_ptr<SystemMonitor> sm;
		std::shared_ptr<LinuxVM> vm;
		
		Process parent;
		std::unique_ptr<Process> child;
		std::shared_ptr<std::vector<uint8_t>> executable;
		addr_t start, mmap, last_chance;
		uint32_t page_loop{};
		std::vector<uint8_t> stored_bytes{};
		std::unique_ptr<ProcessChangeEvent> cr3_change;
		std::unique_ptr<ProcessBreakpointEvent> mmap_break, last_chance_break;
		std::unique_ptr<SyscallEvent> execveat_call;
		std::atomic<bool> forked{}, mapped{}, executed{}, finished{};
		std::chrono::time_point<std::chrono::high_resolution_clock> timer{};
	};
}

