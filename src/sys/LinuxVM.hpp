#ifndef __LINUX_VM_H
#define __LINUX_VM_H

#include <libvmtrace.hpp>
#include <vector>
#include <boost/bind.hpp>
#include <chrono>

namespace libvmtrace
{
	class LinuxVM;

	enum CodeInjectionType
	{
		PAGE_FAULT, FORK_EXEC, NOPE
	};

	struct CodeInjection
	{
		CodeInjectionType type;

		vmi_pid_t target_pid;
		vmi_pid_t child_pid;
		addr_t target_dtb;
		addr_t task_struct;

		std::vector<addr_t> target_addrs;
		std::vector<std::pair<addr_t, addr_t>> result_addrs;

		addr_t entry_addr;

		addr_t breakpoint1;
		addr_t breakpoint_pa1;

		addr_t breakpoint2;
		addr_t breakpoint_pa2;

		addr_t breakpoint3;
		addr_t breakpoint_pa3;

		char* saved_code = nullptr;
		char* inject_code = nullptr;
		char* tmp = nullptr;

		std::shared_ptr<Patch> patch;
		std::shared_ptr<ProcessBreakpointEvent> bp;
		bool recover{};

		size_t instr_size;
		size_t total_page_text;

		EventListener* evl;

		ProcessBreakpointEvent* bp1;
		ProcessBreakpointEvent* bp2;
		ProcessBreakpointEvent* bp3;

		x86_registers_t regs;

		std::string command;

		std::chrono::time_point<std::chrono::high_resolution_clock> start;
		std::chrono::time_point<std::chrono::high_resolution_clock> start1;
	};

	struct OpenFile
	{
		std::string path;
		uint64_t fd;
		uint32_t mode;
		bool write;
	};

	class SyscallProcessor : public EventListener
	{
		public:
			SyscallProcessor(LinuxVM* lvm) : _lvm(lvm) {}
			bool callback(Event* ev, void* data);
		private:
			LinuxVM* _lvm;
	};

	class CodeInjectionProcessorCr3 : public EventListener
	{
		public:
			CodeInjectionProcessorCr3(LinuxVM* lvm) : _lvm(lvm) {}
			bool callback(Event* ev, void* data);
		private:
			LinuxVM* _lvm;
	};

	class CodeInjectionProcessorInt3 : public EventListener
	{
		public:
			CodeInjectionProcessorInt3(LinuxVM* lvm) : _lvm(lvm) {}
			bool callback(Event* ev, void* data);
		private:
			LinuxVM* _lvm;
	};

	class LinuxVM : public OperatingSystem, public std::enable_shared_from_this<LinuxVM>
	{
	public:
		LinuxVM(std::shared_ptr<SystemMonitor> sm);
		~LinuxVM();

        	Process GetCurrentProcess(addr_t current_process) const;
		std::vector<Process> GetProcessList();
		std::vector<net::NetworkConnection> GetNetworkConnections(const Process& p, const ConnectionType type);
		std::vector<OpenFile> GetOpenFiles(const Process& p, int filterfd = -1) const;
		std::vector<vm_area> GetMMaps(const Process& p);

		status_t RegisterSyscall(SyscallEvent& ev);
		status_t DeRegisterSyscall(SyscallEvent& ev);
		bool ProcessSyscall(SyscallBreakpoint* ev, void* data, vmi_instance_t);

		status_t PauseSyscall(SyscallEvent& ev);
		status_t ResumeSyscall(SyscallEvent& ev);

		status_t RegisterProcessChange(ProcessChangeEvent& ev);
		status_t DeRegisterProcessChange(ProcessChangeEvent& ev);

		inline std::shared_ptr<SystemMonitor> GetSystemMonitor() const { return _sm; }

		addr_t GetSymbolAddrVa(const std::string binaryPath, const Process& p, const std::string symbolName, const bool onlyFunctions = true);
		addr_t GetSymbolAddrPa(const std::string binaryPath, const Process& p, const std::string symbolName, const bool onlyFunctions = true);
		addr_t GetSymbolAddrVa(const uint8_t* binary, const Process& p, const std::string path, const std::string symbolName, const bool onlyFunctions = true);

		void PopulatePageFaultAdress(const vmi_pid_t pid, const addr_t target, EventListener* evl);
		status_t InvokePageFault(uint64_t total_address_per_inst);

		status_t InvokeCommand(const vmi_pid_t pid, std::string command, EventListener* evl);

		Process InjectELF(const Process& p, std::vector<uint8_t>& executable);
		Process InjectELF(const Process& p, const std::string executable);
		void ExtractFile(const Process& p, const std::string file, const std::string out);
		std::vector<uint8_t> ExtractFile(const Process& p, const std::string file);

		bool ProcessCR3CodeInjection(vmi_instance_t vmi, vmi_event_t *event);
		bool ProcessInt3CodeInjection(ProcessBreakpointEvent* ev, void* data, vmi_instance_t vmi);

		std::pair<addr_t, addr_t> GetCodeArea(vmi_pid_t pid);
	private:
		addr_t _tgid_offset, _name_offset, _mm_offset, _tasks_offset, _parent_offset, _pgd_offset, _real_cred_offset, _uid_offset, _fs_offset, _pwd_offset;
		addr_t _dentry_d_name_offset, _dentry_parent_offset;
		addr_t _mount_mnt_mountpoint_offset, _mount_mnt_parent_offset, _mount_mnt_offset;
		addr_t _files_offset, _fdt_offset, _fd_offset, _f_mode_offset, _f_path_offset;
		addr_t _private_data_offset, _sk_offset, _u1_offset, _u3_offset;
		addr_t _vm_end_offset, _vm_flags_offset, _vm_file_offset, _vm_pgoff_offset, _vm_next_offset, _exe_file_offset;
		addr_t _code_start_offset, _code_end_offset;

		addr_t _thread_struct_offset, _sp_offset, _sp0_offset, _sp_on_pt_regs_offset, _ip_on_pt_regs_offset, _current_task_offset;
		addr_t _socket_type_offset, _socket_family;

		std::string d_path(addr_t path, vmi_instance_t vmi) const;
		uint32_t create_path(addr_t dentry, addr_t mnt, char* buf, vmi_instance_t vmi) const;
		Process taskstruct_to_Process(addr_t current_process, vmi_instance_t vmi) const;

		addr_t GetSyscallAddrVA(unsigned int syscall_nr, bool is32bit, vmi_instance_t vmi);
		addr_t GetSyscallAddrPA(unsigned int syscall_nr, bool is32bit, vmi_instance_t vmi);

		status_t InvokeCodeInjection(CodeInjectionType type, const vmi_pid_t pid, const addr_t target, std::string command, EventListener* evl);

		std::unordered_map<int, SyscallEvent*> _SyscallEvents64;
		std::unordered_map<int, SyscallEvent*> _SyscallEvents32;
		std::map<int, SyscallBreakpoint> _Syscallbps64;
		std::map<int, SyscallBreakpoint> _Syscallbps32;
		SyscallProcessor _syscallProc;

		uint64_t _total_address_per_inst;

		ElfHelper* _eh;
		std::string _binaryPathTemp;
		char* _binaryMap;

		ProcessChangeEvent* _process_change;
		std::vector<CodeInjection> _code_injections;
		CodeInjectionProcessorCr3 _code_injection_proc_cr3;
		CodeInjectionProcessorInt3 _code_injection_proc_int3;
	};

	extern uint8_t linux_agent_start[] asm("_binary____bin_linux_file_extraction_agent_start");
	extern uint8_t linux_agent_end[] asm("_binary____bin_linux_file_extraction_agent_end");
}

#endif
