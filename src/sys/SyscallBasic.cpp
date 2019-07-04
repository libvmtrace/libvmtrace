#include <string>
#include <sstream>
#include <libvmi/libvmi.h>

#include "sys/SyscallBasic.hpp"

void SyscallBasic::PreProcess(const LinuxVM& lvm, uint64_t nr, vmi_instance_t vmi)
{
	_nr = nr;
	_name =  "";

	// TODO: seems to be buggy
	// vmi_dtb_to_pid(vmi, regs_.cr3, &pid_);
}

void SyscallBasic::PostProcess(const LinuxVM& lvm, unsigned vcpu, vmi_instance_t vmi, x86_registers_t* regs)
{
	_ret = regs->rax;
}

vmi_pid_t SyscallBasic::GetPid(vmi_instance_t vmi) 
{
	if(!_got_pid)
	{
		vmi_dtb_to_pid(vmi, _regs.cr3, &_pid);
		_got_pid = true;
	}
	return _pid;
}

SyscallBasic::SyscallBasic(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, x86_registers_t* regs):
							_vcpu(vcpu),
							_ret(0),
							_is32bit(is32bit),
							_pagefault(false)
{
	_withRet = true;
	_got_pid = false;

	//vmi_v2pcache_flush(vmi,~0ull);
	if (before_call)
	{
		memcpy(&_regs, regs, sizeof(x86_registers_t));
		addr_t stack_addr_pa = 0;

		if(_withRet)
			vmi_pagetable_lookup(vmi, _regs.cr3, _regs.rsp, &stack_addr_pa);

		if (_is32bit)
		{

		}
		else
		{
			if(_withRet)
				vmi_read_64_pa(vmi, stack_addr_pa, &_rip);

			_p_[0] = _regs.rdi;
			_p_[1] = _regs.rsi;
			_p_[2] = _regs.rdx;
			_p_[3] = _regs.rcx;
			_p_[4] = _regs.r8;
			_p_[5] = _regs.r9;
		}
	}
	else
	{

	}
}

SyscallBasic::SyscallBasic(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, bool withRet, x86_registers_t* regs) :
							SyscallBasic::SyscallBasic(vmi, vcpu, before_call, is32bit, regs)
{
	_withRet = withRet;
}

SyscallBasic::~SyscallBasic()
{

}