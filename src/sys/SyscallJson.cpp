
#include <sys/SyscallJson.hpp>
#include <util/utils.hpp>

namespace libvmtrace
{
	using namespace util;

	std::string SyscallJson::ExtractString(vmi_instance_t vmi, addr_t ptr) 
	{
		access_context_t ctx;
		char* buf = nullptr;

		ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
		ctx.dtb = SyscallBasic::GetRegisters().cr3;
		// ctx.dtb &= ~0x1fff;

		ctx.addr = ptr;

		buf = vmi_read_str(vmi, &ctx);
		if (buf == nullptr)
		{
			_pagefault = true;
			return string("ERROR");
		}

		string ret = escape_json(buf);
		free(buf);
		return ret;
	}

	bool invalidChar (char c)
	{
		return !(c>=0 && c <128);
	}

	std::string SyscallJson::ExtractBuf(vmi_instance_t vmi, addr_t ptr, size_t size)
	{
		char* buf = nullptr;
		access_context_t ctx;

		ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
		ctx.dtb = SyscallBasic::GetRegisters().cr3;
		ctx.addr = ptr;

		buf = new char[size];

		size_t read = 0;

		if (vmi_read(vmi, &ctx, size, buf, &read) != VMI_SUCCESS) 
		{
			_pagefault = true;
			return std::string("ERROR");
		}

		if ( size == read) 
		{
			std::string str = string(buf, size);
			str.erase(remove_if(str.begin(), str.end(), invalidChar), str.end());

			std::string ret = escape_json(str);
			free(buf);
			return ret;
		}

		return std::string("ERROR");
	}

	void SyscallJson::ToJsonOpen(vmi_instance_t vmi)
	{
		std::string path = ExtractString(vmi, SyscallBasic::GetParameter(0));

		_writer.Key("path");
		_writer.String(path.c_str());

		reg_t flags = SyscallBasic::GetParameter(1);

		// https://stackoverflow.com/questions/22008229/bitwise-or-in-linux-open-flags
		// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h
		switch (flags & 0x3) 
		{
			case 0:
				_writer.Key("mode");
				_writer.String("r-");
				break;
			case 1:
				_writer.Key("mode");
				_writer.String("-w");
				break;
			case 2:
				_writer.Key("mode");
				_writer.String("rw");
				break;
			default:
				_writer.Key("mode");
				_writer.String("--");
				break;
		}
	}

	void SyscallJson::ToJsonExecve(vmi_instance_t vmi)
	{
		access_context_t ctx;
		ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
		ctx.dtb = SyscallBasic::GetRegisters().cr3;

		std::string path = ExtractString(vmi, SyscallBasic::GetParameter(0));
		_writer.Key("path");
		_writer.String(path.c_str());

		_writer.Key("args");
		_writer.StartArray();
		for (int i = 0 ; i < 100 ; i++)
		{
			addr_t tmp;
			ctx.addr = SyscallBasic::GetParameter(1)+i*8;
			vmi_read_64(vmi, &ctx, &tmp);
			if (tmp == 0)
				break;

			std::string tmp2 = ExtractString(vmi, tmp);
			_writer.String(tmp2.c_str());
		}
		_writer.EndArray();

		_writer.Key("env");
		_writer.StartArray();
		for (int i = 0 ; i < 100 ; i++)
		{
			addr_t tmp;
			ctx.addr = SyscallBasic::GetParameter(2)+i*8;
			vmi_read_64(vmi, &ctx, &tmp);
			if (tmp == 0)
				break;

			std::string tmp2 = ExtractString(vmi, tmp);
			_writer.String(tmp2.c_str());
		}
		_writer.EndArray();
	}

	void SyscallJson::ToJsonBind(vmi_instance_t vmi, addr_t sockaddr) 
	{
		access_context_t ctx;
		uint16_t sport;

		struct sockaddr sa;
		struct sockaddr_in* caster = (struct sockaddr_in*)&sa;

		ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
		ctx.dtb = SyscallBasic::GetRegisters().cr3;
		ctx.addr = sockaddr;

		size_t read = 0;
		vmi_read(vmi, &ctx, sizeof(struct sockaddr), &sa, &read);
		sport = ntohs(caster->sin_port);

		_writer.Key("path");
		_writer.Uint(sport);

		if (sa.sa_family == AF_INET) 
		{
			_writer.Key("address");
			_writer.String(inet_ntoa(caster->sin_addr));
		} 
		else if (sa.sa_family == AF_INET6) 
		{
			// TODO: finish this branch.
		}

		return;
	}

	void SyscallJson::ToJsonConnect(vmi_instance_t vmi, addr_t socka) 
	{
		access_context_t ctx;
		uint16_t sport;

		struct sockaddr sa;

		ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
		ctx.dtb = SyscallBasic::GetRegisters().cr3;
		ctx.addr = socka;

		size_t read = 0;
		vmi_read(vmi, &ctx, sizeof(struct sockaddr), &sa, &read);

		// https://stackoverflow.com/questions/1276294/getting-ipv4-address-from-a-sockaddr-structure
		if (sa.sa_family == AF_INET) 
		{
			struct sockaddr_in* caster = (struct sockaddr_in*)&sa;

			sport = ntohs(caster->sin_port);
			_writer.Key("port");
			_writer.Uint(sport);

			_writer.Key("address");
			_writer.String(inet_ntoa(caster->sin_addr));
		} 
		else if (sa.sa_family == AF_INET6) 
		{
			struct sockaddr_in6* caster6 = (struct sockaddr_in6*)&sa;

			sport = ntohs(caster6->sin6_port);
			_writer.Key("port");
			_writer.Uint(sport);

			char s[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &(caster6->sin6_addr), s, INET6_ADDRSTRLEN);
			_writer.Key("address");
			_writer.String(s);
		}
		else if (sa.sa_family == AF_UNIX)
		{
			_writer.Key("path");
			_writer.String(sa.sa_data);
		}
	}

	void SyscallJson::ToJsonRead(vmi_instance_t vmi) 
	{
		int size =  SyscallBasic::GetRet();
		size = min(size, 4096);

		_writer.Key("fd");
		_writer.Uint(SyscallBasic::GetParameter(0));

		_writer.Key("size");
		_writer.Uint(size);

		if (size > 0)
		{
			_writer.Key("buf");
			_writer.String(ExtractBuf(vmi, SyscallBasic::GetParameter(1), size).c_str());
		}
		else
		{
			_writer.Key("buf");
			_writer.String("");
		}
	}

	void SyscallJson::ToJsonWrite(vmi_instance_t vmi) 
	{
		_writer.Key("fd");
		_writer.Uint(SyscallBasic::GetParameter(0));
		_writer.Key("size");
		_writer.Uint(SyscallBasic::GetParameter(2));
		_writer.Key("buf");
		_writer.String(ExtractBuf(vmi, SyscallBasic::GetParameter(1), SyscallBasic::GetParameter(2)).c_str());
	}

	void SyscallJson::ToJsonStat(vmi_instance_t vmi)
	{
		_writer.Key("path");
		_writer.String(ExtractString(vmi, SyscallBasic::GetParameter(0)).c_str());
	}

	void SyscallJson::ToJsonCompat_Socketcall(vmi_instance_t vmi)
	{
		// http://lxr.free-electrons.com/source/net/socket.c?v=3.16
		access_context_t ctx;
		addr_t sockaddr = 0;

		ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
		ctx.dtb = SyscallBasic::GetRegisters().cr3;
		ctx.addr = SyscallBasic::GetParameter(1)+1*4;

		vmi_read_32 (vmi, &ctx, (uint32_t*)&sockaddr);

		// http://lxr.free-electrons.com/source/include/uapi/linux/net.h?v=3.16
		_writer.Key("socketcall");
		if (SyscallBasic::GetParameter(0) == 1) 
		{
			_writer.String("socket");
		} 
		else if (SyscallBasic::GetParameter(0) == 2) 
		{
			_writer.String("bind");
			ToJsonBind(vmi, sockaddr);
		} 
		else if (SyscallBasic::GetParameter(0) == 3) 
		{
			_writer.String("connect");
			ToJsonConnect(vmi, sockaddr);
		} 
		else if (SyscallBasic::GetParameter(0) == 4) 
		{
			_writer.String("listen");
		} 
		else if (SyscallBasic::GetParameter(0) == 5) 
		{
			_writer.String("connect");
		} 
		else if (SyscallBasic::GetParameter(0) == 6) 
		{
			_writer.String("getsockname");
		} 
		else if (SyscallBasic::GetParameter(0) == 7) 
		{
			_writer.String("getpeername");
		} 
		else if (SyscallBasic::GetParameter(0) == 8) 
		{
			_writer.String("socketpair");
		} 
		else if (SyscallBasic::GetParameter(0) == 9) 
		{
			_writer.String("send");
		} 
		else if (SyscallBasic::GetParameter(0) == 10) 
		{
			_writer.String("recv");
		} 
		else if (SyscallBasic::GetParameter(0) == 11) 
		{
			_writer.String("sendto");
		} 
		else if (SyscallBasic::GetParameter(0) == 12) 
		{
			_writer.String("recvfrom");
		} 
		else if (SyscallBasic::GetParameter(0) == 13) 
		{
			_writer.String("shutdown");
		} 
		else if (SyscallBasic::GetParameter(0) == 18) 
		{
			_writer.String("accept4");
		}
		else
		{
			_writer.String("Unknown");
		}
	}

	void SyscallJson::PreProcess(const LinuxVM& lvm, uint64_t nr, vmi_instance_t vmi)
	{
		SyscallBasic::PreProcess(lvm, nr, vmi);

		vmi_v2pcache_flush(vmi,~0ull);

		_pid = SyscallBasic::GetPid(vmi);

		_writer.Key("syscall_nr");
		_writer.Uint(SyscallBasic::GetNr());
		_writer.Key("syscall_name");
		_writer.String(SyscallBasic::GetName().c_str());
		_writer.Key("dtb");
		_writer.String(int_to_hex(SyscallBasic::GetRegisters().cr3).c_str());
		_writer.Key("rsp");
		_writer.String(int_to_hex(SyscallBasic::GetRegisters().rsp).c_str());
		_writer.Key("rip");
		_writer.String(int_to_hex(SyscallBasic::GetRegisters().rip).c_str());
		_writer.Key("pid");
		_writer.Uint(_pid);

		if (SyscallBasic::Is32Bit())
		{
			//http://lxr.free-electrons.com/source/arch/x86/syscalls/syscall_32.tbl?v=3.16
			if (SyscallBasic::GetNr() == 5)
				ToJsonOpen(vmi);
			if (SyscallBasic::GetNr() == 59)
				ToJsonExecve(vmi);
			if (SyscallBasic::GetNr() == 102)
				ToJsonCompat_Socketcall(vmi);
			if (SyscallBasic::GetNr() == 4)
				ToJsonWrite(vmi);
		}
		else
		{
			if (SyscallBasic::GetNr() == 1)
				ToJsonWrite(vmi);
			if (SyscallBasic::GetNr() == 2)
				ToJsonOpen(vmi);
			if (SyscallBasic::GetNr() == 4)
				ToJsonStat(vmi);
			if (SyscallBasic::GetNr() == 59)
				ToJsonExecve(vmi);
			if (SyscallBasic::GetNr() == 49)
				ToJsonBind(vmi, SyscallBasic::GetParameter(1));
			if (SyscallBasic::GetNr() == 42)
				ToJsonConnect(vmi, SyscallBasic::GetParameter(1));
		}
	}

	void SyscallJson::PostProcess(const LinuxVM& lvm, unsigned vcpu, vmi_instance_t vmi, x86_registers_t* regs) 
	{
		SyscallBasic::PostProcess(lvm, vcpu, vmi, regs);
		_writer.Key("return_value");
		_writer.Uint(SyscallBasic::GetRet());
	}

	const string SyscallJson::ToJson()
	{
		_writer.EndObject();

		return _s.GetString();
	}

	SyscallJson::SyscallJson(vmi_instance_t vmi, unsigned int vcpu, bool before_call, bool is32bit, bool withRet, x86_registers_t* regs  ):
								SyscallBasic::SyscallBasic(vmi, vcpu, before_call, is32bit, withRet, regs),
								_writer(_s)
	{
		_writer.StartObject();
	}
}

