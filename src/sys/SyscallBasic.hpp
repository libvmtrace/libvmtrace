
#ifndef __SYSCALL_BASIC_H_
#define __SYSCALL_BASIC_H_

#include <string>
#include <sstream>
#include <iostream>

namespace libvmtrace
{
	class LinuxVM;

	/* stolen from the linux kernel. */
	struct pt_regs
	{
		unsigned long r15;
		unsigned long r14;
		unsigned long r13;
		unsigned long r12;
		unsigned long bp;
		unsigned long bx;
		unsigned long r11;
		unsigned long r10;
		unsigned long r9;
		unsigned long r8;
		unsigned long ax;
		unsigned long cx;
		unsigned long dx;
		unsigned long si;
		unsigned long di;
		unsigned long orig_ax;
		unsigned long ip;
		unsigned long cs;
		unsigned long flags;
		unsigned long sp;
		unsigned long ss;
	};


	class SyscallBasic
	{
		public:
			SyscallBasic(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, x86_registers_t* regs);
			SyscallBasic(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, bool withRet, x86_registers_t* regs);
			virtual ~SyscallBasic();
			virtual void PreProcess(const LinuxVM& lvm, uint64_t nr, vmi_instance_t vmi);
			virtual void PostProcess(const LinuxVM& lvm, unsigned int vcpu, vmi_instance_t, x86_registers_t* regs);

			vmi_pid_t GetPid(vmi_instance_t vmi);

			uint64_t GetNr() const { return _nr; }
			uint64_t GetRet() const { return _ret; }
			uint64_t GetDtb() const { return _regs.cr3; }
			uint64_t GetStackAddr() const { return _rsp; }
			uint64_t GetRip() const { return _rip; }
			std::string GetName() const {  return _name;  }
			uint64_t GetParameter(int i) const { return _p_[i]; }
			x86_registers_t GetRegisters() const { return _regs; };
			bool Is32Bit() const { return _is32bit; };
			bool PageFault() const { return _pagefault; }
			
			virtual const std::string ToJson() { 
				std::string tmp =  "{\"syscall_nr\":" + std::to_string(_nr); 
				if (_withRet) 
					tmp = tmp + ", \"ret\":" + std::to_string(_ret);
				tmp = tmp + "}";
				return tmp;
			} ;

		protected:
			uint64_t _nr;
			std::string _name;
			x86_registers_t _regs; 
			unsigned int _vcpu;
			uint64_t _p_[6];
			uint64_t _ret; // return value
			uint64_t _rip; // pointer to last user space instruction
			uint64_t _rsp;
			bool _is32bit;
			bool _withRet;
			vmi_pid_t _pid;
			bool _got_pid;
			bool _pagefault;
	};
}

#endif

