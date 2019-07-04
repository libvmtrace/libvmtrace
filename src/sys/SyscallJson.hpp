#ifndef __SYSCALL_JSON_H_
#define __SYSCALL_JSON_H_

#include <libvmi/libvmi.h>
#include <string>
#include <sstream>

#include "libvmtrace.hpp"

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidjson;
using namespace std;

class LinuxVM;

class SyscallJson : public SyscallBasic
{
	public:
		SyscallJson(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, x86_registers_t* regs);
		SyscallJson(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, bool withRet, x86_registers_t* regs);
		~SyscallJson(){ };
		void PreProcess(const LinuxVM& lvm, uint64_t nr, vmi_instance_t vmi);
		void PostProcess(const LinuxVM& lvm, unsigned int vcpu, vmi_instance_t, x86_registers_t* regs);

		const string ToJson();
		vmi_pid_t GetPid() const
		{ 
			return _pid; 
		}

	private:
		std::string ExtractString(vmi_instance_t vmi, addr_t ptr);
		std::string ExtractBuf(vmi_instance_t vmi, addr_t ptr, size_t size);

		void ToJsonOpen(vmi_instance_t vmi);
		void ToJsonExecve(vmi_instance_t vmi);
		void ToJsonBind(vmi_instance_t, addr_t sockaddr);
		void ToJsonConnect(vmi_instance_t, addr_t sockaddr);
		void ToJsonRead(vmi_instance_t);
		void ToJsonWrite(vmi_instance_t);
		void ToJsonStat(vmi_instance_t);
		void ToJsonCompat_Socketcall(vmi_instance_t);

		vmi_pid_t _pid;

		StringBuffer _s;
		Writer<StringBuffer> _writer;
};

#endif
