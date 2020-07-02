
#include <sys/LinuxVM.hpp>
#include <sys/types.h>
#include <sys/LinuxELFInjector.hpp>
#include <sys/LinuxFileExtractor.hpp>
#include <chrono>

namespace libvmtrace
{
	using namespace std; 
	using namespace util;

	// mov rax rbx
	// static char code[] = "\x48\x8B\x03";

	/*
	push rax
	mov rax, <address>
	mov rax, [rax]
	pop rax
	*/
	// static char code_page_fault[]= "\x50\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x8B\x00\x58";
	// static char code_page_fault2[] = "\x50\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x48\x8B\x00\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x48\x8B\x00\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x48\x8B\x00\x58";

	static char push_rax[] = "\x50";
	static char mov_rax_addr[] = "\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x48\x8B\x00";
	static char pop_rax[] = "\x58";

	// static size_t total_address_per_inst = 2;
	// static char code_syscall[] = "\x0f\x05\xCC\x0f\x05";
	/*
	push rax
	mov rax, 0x3A // vfork
	syscall
	xchg rax, [rsp] // restore rax
	int 3 // breakpoint
	mov rax, 0x3B // exec
	syscall
	mov rax, 0x3C // exit
	syscall
	*/
	static char code_syscall_vfork_exec[] = "\x50\x48\xC7\xC0\x3A\x00\x00\x00\x0F\x05\x48\x87\x04\x24\xCC\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\x48\xC7\xC0\x3C\x00\x00\x00\x0F\x05";
	static char bin[] = "/bin/bash";
	static char param1[] = "-c";

	LinuxVM::LinuxVM(SystemMonitor* sm) : OperatingSystem(sm), _syscallProc(this), 
											_process_change(nullptr), 
											_code_injection_proc_cr3(this), _code_injection_proc_int3(this)
	{
		vmi_instance_t vmi = sm->Lock();

		vmi_get_offset(vmi, (char*)"linux_name", &_name_offset);
		vmi_get_kernel_struct_offset(vmi,"task_struct", "mm", &_mm_offset);
		vmi_get_offset(vmi, (char*)"linux_tasks", &_tasks_offset);
		vmi_get_offset(vmi, (char*)"linux_pgd", &_pgd_offset);
		vmi_get_kernel_struct_offset(vmi,"task_struct", "tgid", &_tgid_offset);
		vmi_get_kernel_struct_offset(vmi,"task_struct", "real_parent", &_parent_offset);
		vmi_get_kernel_struct_offset(vmi,"task_struct", "real_cred", &_real_cred_offset);
		vmi_get_kernel_struct_offset(vmi,"cred", "uid", &_uid_offset);
		vmi_get_kernel_struct_offset(vmi,"task_struct", "fs", &_fs_offset);
		vmi_get_kernel_struct_offset(vmi,"fs_struct", "pwd", &_pwd_offset);

		vmi_get_kernel_struct_offset(vmi,"dentry", "d_name",&_dentry_d_name_offset);
		vmi_get_kernel_struct_offset(vmi,"dentry", "d_parent",&_dentry_parent_offset);

		vmi_get_kernel_struct_offset(vmi,"task_struct", "files",&_files_offset);

		vmi_get_kernel_struct_offset(vmi, "current_task", NULL, &_current_task_offset);

		vmi_get_kernel_struct_offset(vmi,"mm_struct", "exe_file", &_exe_file_offset);
		vmi_get_kernel_struct_offset(vmi,"mm_struct", "start_code", &_code_start_offset);
		vmi_get_kernel_struct_offset(vmi,"mm_struct", "end_code", &_code_end_offset);

		vmi_get_kernel_struct_offset(vmi,"file", "private_data",&_private_data_offset);
		vmi_get_kernel_struct_offset(vmi,"socket", "sk",&_sk_offset);
		vmi_get_kernel_struct_offset(vmi,"sock_common", "u1",&_u1_offset);
		vmi_get_kernel_struct_offset(vmi,"sock_common", "u3",&_u3_offset);
		vmi_get_kernel_struct_offset(vmi,"socket", "type",&_socket_type_offset);
		vmi_get_kernel_struct_offset(vmi,"sock_common", "skc_family",&_socket_family);

		vmi_get_kernel_struct_offset(vmi,"files_struct", "fdt",&_fdt_offset);
		vmi_get_kernel_struct_offset(vmi,"fdtable", "fd",&_fd_offset);
		vmi_get_kernel_struct_offset(vmi,"file", "f_path",&_f_path_offset);
		vmi_get_kernel_struct_offset(vmi,"file", "f_mode",&_f_mode_offset);

		vmi_get_kernel_struct_offset(vmi,"vm_area_struct","vm_end",&_vm_end_offset);
		vmi_get_kernel_struct_offset(vmi,"vm_area_struct","vm_flags",&_vm_flags_offset);
		vmi_get_kernel_struct_offset(vmi,"vm_area_struct","vm_file",&_vm_file_offset);
		vmi_get_kernel_struct_offset(vmi,"vm_area_struct","vm_pgoff",&_vm_pgoff_offset);
		vmi_get_kernel_struct_offset(vmi,"vm_area_struct","vm_next",&_vm_next_offset);

		vmi_get_kernel_struct_offset(vmi,"task_struct", "thread",&_thread_struct_offset);
		vmi_get_kernel_struct_offset(vmi,"thread_struct", "sp",&_sp_offset);
		vmi_get_kernel_struct_offset(vmi,"thread_struct", "sp0",&_sp0_offset);
		vmi_get_kernel_struct_offset(vmi,"pt_regs", "sp",&_sp_on_pt_regs_offset);
		vmi_get_kernel_struct_offset(vmi,"pt_regs", "ip",&_ip_on_pt_regs_offset);

		_eh = new ElfHelper();

		_total_address_per_inst = 2;

		sm->Unlock();
	}

	Process LinuxVM::GetCurrentProcess(addr_t gs_base) const
	{
		vmi_instance_t vmi = _sm->Lock();

                addr_t current_process;
		addr_t cpptr = gs_base + _current_task_offset;
                vmi_read_addr_va(vmi, cpptr, 0, &current_process);

		Process p = taskstruct_to_Process(current_process, vmi);
                _sm->Unlock();
		return p;
	}

	Process LinuxVM::taskstruct_to_Process(addr_t current_process, vmi_instance_t vmi) const
	{
		status_t status;
		vmi_pid_t pid = 0;
		addr_t dtb = 0;
		vmi_pid_t parent_pid = 0;
		int uid = 0;

		status = vmi_read_32_va(vmi, current_process + _tgid_offset, 0, (uint32_t*)&pid);
		if(status == VMI_FAILURE)
		{
			throw std::runtime_error("VMI failure when reading PID");
		}

		addr_t tmp2;
		vmi_read_addr_va(vmi, current_process + _parent_offset, 0, &tmp2);
		vmi_read_32_va(vmi, tmp2 + _tgid_offset, 0, (uint32_t*)&parent_pid);

		addr_t tmp3;
		vmi_read_addr_va(vmi, current_process + _real_cred_offset, 0, &tmp3);
		vmi_read_32_va(vmi, tmp3 + _uid_offset, 0, (uint32_t*)&uid);

		char* procname = vmi_read_str_va(vmi, current_process + _name_offset, 0);
		string name = "";
		if(procname)
		{
			name = string(procname);
			free(procname);
			procname = NULL;
		}

		//vmi_pid_to_dtb(vmi, pid, &dtb);

		addr_t mm;
		vmi_read_addr_va(vmi, current_process + _mm_offset, 0, &mm);
		addr_t pgd;
		vmi_read_addr_va(vmi, mm + _pgd_offset, 0, &pgd);

		vmi_translate_kv2p(vmi, pgd, &dtb);

		// cout << dec << pid << " : " << parent_pid << " - " << name << endl;

		addr_t tmp4;
		vmi_read_addr_va(vmi, current_process + _fs_offset, 0, &tmp4);
		string pwd = d_path(tmp4 + _pwd_offset, vmi);

		addr_t tmp5;
		vmi_read_addr_va(vmi, mm+_exe_file_offset, 0, &tmp5);
		string path = d_path(tmp5 + _f_path_offset, vmi);
		Process p(current_process, pid, dtb, name, path, parent_pid, uid, pwd);
		return p;
	}

	vector<Process> LinuxVM::GetProcessList(void)
	{
		vector<Process> processes;
		status_t status;

		addr_t list_head = 0, next_list_entry = 0;
		addr_t current_process = 0;

		vmi_instance_t vmi = _sm->Lock();

		addr_t tmp1;
		vmi_translate_ksym2v(vmi, "init_task", &tmp1);
		list_head = tmp1 + _tasks_offset;

		//auto start = std::chrono::high_resolution_clock::now();
		next_list_entry = list_head;
		// vmi_pidcache_flush(vmi);
		vmi_pause_vm(vmi);
		do
		{
			current_process = next_list_entry - _tasks_offset;
			try {
				Process p = taskstruct_to_Process(current_process, vmi);
				processes.push_back(p);
			} catch(std::runtime_error &e) {
				break;
			}				

			status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
			if(status == VMI_FAILURE)
			{
				cerr << "Proclist: could not follow next pointer" << endl;
				break;
			}
		}
		while(next_list_entry != list_head);
		vmi_resume_vm(vmi);
		//auto end = std::chrono::high_resolution_clock::now();
		//auto dur = end - start;
		//auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();

		//cout << "proclist took : " << dec << ms << endl;


		_sm->Unlock();

		return processes;
	}

	pair<addr_t, addr_t> LinuxVM::GetCodeArea(vmi_pid_t pid)
	{
		vmi_instance_t vmi = _sm->Lock();

		pair<addr_t, addr_t> return_value;

		vector<Process> processes = GetProcessList();

		bool found = false;
		for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
		{
			if((*it).GetPid() == pid)
			{
				addr_t mm = 0;
				if(vmi_read_addr_va(vmi, (*it).GetTaskStruct() + _mm_offset, 0, &mm) == VMI_SUCCESS && mm != 0)
				{
					addr_t start = 0;
					addr_t end = 0;

					if(vmi_read_addr_va(vmi, mm + _code_start_offset, 0, &start) == VMI_SUCCESS)
					{
						if(vmi_read_addr_va(vmi, mm + _code_end_offset, 0, &end) == VMI_SUCCESS)
						{
							found = true;
							return_value = make_pair(start, end);
							break;
						}
					}
				}
				else
				{
					break;
				}
			}
		}

		if(!found)
			return_value = make_pair(0, 0);

		_sm->Unlock();

		return return_value;
	}

	vector<net::NetworkConnection> LinuxVM::GetNetworkConnections(const Process& p, const ConnectionType type)
	{
		vector<net::NetworkConnection> networkconnections;

		vmi_instance_t vmi = _sm->Lock();

		uint32_t max_fds = 0;
		addr_t files = 0;
		vmi_read_64_va(vmi, p.GetTaskStruct() + _files_offset, 0, &files);

		// http://lxr.free-electrons.com/source/include/linux/fdtable.h?v=3.16#L24
		addr_t fdt = 0;
		vmi_read_64_va(vmi, files + _fdt_offset, 0, &fdt);
		vmi_read_32_va(vmi, fdt + 0, 0, &max_fds);

		addr_t fd = 0;
		vmi_read_64_va(vmi, fdt + _fd_offset, 0, &fd);

		int count = 0;
		for(uint32_t it = 3; it < max_fds ; it++)
		{
			addr_t file = 0;
			uint32_t mode;

			vmi_read_64_va(vmi, fd + it*8, 0, &file);
			if (file == 0)
			{
				count++;
				continue;
			}

			//http://lxr.free-electrons.com/source/include/linux/fs.h?v=3.16#L747
			vmi_read_32_va(vmi, file + _f_mode_offset, 0, &mode);
			string path = d_path(file + _f_path_offset, vmi);
			if (path.size() == 0)
			{
				count++;
				continue;
			}

			vector<string> compare;

			if(type == TCP)
			{
				compare.push_back("TCP");
				compare.push_back("TCPv6");
			}
			else if(type == UDP)
			{
				compare.push_back("UDP");
				compare.push_back("UDPv6");
			}

			if(find(compare.begin(), compare.end(), path) != compare.end())
			{
				// http://lxr.free-electrons.com/source/include/net/sock.h?v=3.16#L125
				addr_t socket, sock;
				uint16_t sport, dport;
				uint32_t saddr, daddr;

				// https://elixir.bootlin.com/linux/latest/source/include/linux/net.h#L63
				uint16_t sock_type;
				// family / domain http://man7.org/linux/man-pages/man2/socket.2.html
				uint16_t family;

				vmi_read_64_va(vmi, file + _private_data_offset, 0, &socket);
				vmi_read_64_va(vmi, socket +  _sk_offset, 0, &sock);
				vmi_read_32_va(vmi, sock +  _u1_offset, 0, &daddr);
				vmi_read_32_va(vmi, sock +  _u1_offset+4, 0, &saddr);
				vmi_read_16_va(vmi, sock + _u3_offset, 0, &dport);
				vmi_read_16_va(vmi, sock + _u3_offset+2, 0, &sport);
				vmi_read_16_va(vmi, socket +  _socket_type_offset, 0, &sock_type);
				vmi_read_16_va(vmi, sock + _socket_family, 0, &family);

				if(family == AF_INET)
				{
					net::NetworkConnection t(family, sock_type, (struct in_addr*)&saddr, (struct in_addr*)&daddr, sport, ntohs(dport));
					networkconnections.push_back(t);
				}
				else if(family == AF_INET6)
				{
					// in6_addr* test = (struct in6_addr*)&saddr;
					// char addr[INET6_ADDRSTRLEN];
					// inet_ntop(AF_INET6, &test, addr, INET6_ADDRSTRLEN);
					// cout << addr << endl;
				}
			}

			// if(path == "RAW" || path == "PACKET")
			// {
			// 	char* temp = new char[100];
			// 	uint16_t dport;
			// 	uint16_t sock_type;
			// 	uint16_t fam;

			// 	// cout << dec << _private_data_offset << endl;
			// 	// cout << hexdumptostring(temp, 100) << endl;
			// 	addr_t socket, sock;
			// 	vmi_read_64_va(vmi, file + _private_data_offset, 0, &socket);
			// 	vmi_read_64_va(vmi, socket +  _sk_offset, 0, &sock);
			// 	vmi_read_16_va(vmi, socket +  _socket_type_offset, 0, &sock_type);
			// 	cout << "T : " << dec << sock_type << endl;
			// 	cout << "PF_PACKET : " << dec << PF_PACKET << endl;
			// 	cout << hex << sock << endl;
			// 	vmi_read_16_va(vmi, sock + _u3_offset+2, 0, &dport);
			// 	vmi_read_16_va(vmi, sock + _socket_family, 0, &fam);
			// 	cout << "fam : " << dec << fam << endl;
			// 	cout << dec << dport << endl;
			// 	vmi_read_va(vmi, sock, 0, 100, temp, NULL);
			// 	cout << hexdumptostring(temp, 100) << endl;
			// 	delete[] temp;
			// }
		}

		_sm->Unlock();

		return networkconnections;
	}

	vector <OpenFile> LinuxVM::GetOpenFiles(const Process& p, int filterfd) const
	{
		vector<OpenFile> openfiles;

		vmi_instance_t vmi = _sm->Lock();

		uint32_t max_fds = 0;
		addr_t files = 0;
		vmi_read_64_va(vmi, p.GetTaskStruct() + _files_offset, 0, &files);

		// https://elixir.bootlin.com/linux/v4.20/source/include/linux/fdtable.h#L27
		addr_t fdt = 0;
		vmi_read_64_va(vmi, files + _fdt_offset, 0, &fdt);
		vmi_read_32_va(vmi, fdt + 0, 0, &max_fds);

		addr_t fd = 0;
		vmi_read_64_va(vmi, fdt + _fd_offset, 0, &fd);

		// int count = 0;
		int minfd = 3;
		if( filterfd >= 0 ) {  // if filterfd is specified, return only this file (if fd exists)
			minfd = filterfd; 
			max_fds = std::min(minfd+1, (int)max_fds);
		}
		//std::cout << "minfd: " << minfd << ", maxfd: " << max_fds << "\n";
		
		for(uint32_t it = minfd; it < max_fds ; it++)
		{
			addr_t file = 0;
			uint32_t mode;

			vmi_read_64_va(vmi, fd + it*8, 0, &file);
			if (file == 0)
			{
				// count++;
				continue;
			}

			//http://lxr.free-electrons.com/source/include/linux/fs.h?v=3.16#L747
			vmi_read_32_va(vmi, file + _f_mode_offset, 0, &mode);
			string path = d_path(file + _f_path_offset, vmi);
			if (path.size() == 0)
			{
				// count++;
				continue;
			}

			bool write = false;
			switch (mode & 0x3) 
			{
				case 1:
					write = true;
					break;
				case 2:
					write = true;
					break;
				default:
					break;
			}
			OpenFile f;
			f.path = path;
			f.fd = it;
			f.mode = mode;
			f.write = write;
			openfiles.push_back(f);
		}

		_sm->Unlock();

		return openfiles;
	}

	string LinuxVM::d_path(addr_t path, vmi_instance_t vmi) const
	{
		// struct_path : http://lxr.free-electrons.com/source/include/linux/path.h#L7
		addr_t mnt;
		addr_t dentry;
		char buf[PATH_MAX];
		memset(buf, 0, sizeof(buf));

		if (path == 0)
			return string("");

		vmi_read_64_va(vmi, path, 0, &mnt);

		vmi_read_64_va(vmi, path+8, 0, &dentry);
		if (dentry == 0)
			return string("");

		// second item in qstr struct
		// http://lxr.free-electrons.com/source/include/linux/dcache.h#L108
		create_path(dentry, buf, vmi);
		if (strlen(buf) == 0)
			return string("");

		return string(buf);
	}

	uint32_t LinuxVM::create_path(addr_t dentry, char* buf, vmi_instance_t vmi) const
	{
		addr_t name;
		char* tmp;
		if (dentry == 0)
			return 0;
		
		vmi_read_64_va(vmi, dentry+_dentry_d_name_offset+8, 0, &name);
		tmp = vmi_read_str_va(vmi, name, 0);
		if (tmp == NULL)
			return 0;
		
		addr_t parent;
		vmi_read_64_va(vmi, dentry+_dentry_parent_offset, 0, &parent);
		if (parent != dentry) 
		{
			create_path(parent, buf, vmi);
		}
		
		if(parent == dentry && tmp[0] == '/') 
		{
			// strcat(buf, tmp);
		} 
		else if (parent == dentry) 
		{
			strcat(buf, tmp);
		}
		
		if(parent != dentry) 
		{
			strcat(buf, "/");
			strcat(buf, tmp);
		}
		
		free(tmp);
		return strlen(buf);
	}

	vector<vm_area> LinuxVM::GetMMaps(const Process& p)
	{
		vector<vm_area> maps;

		vmi_instance_t vmi = _sm->Lock();

		addr_t mm_struct_ptr = 0;
		if(vmi_read_64_va(vmi, p.GetTaskStruct() + _mm_offset, 0, &mm_struct_ptr) != VMI_SUCCESS)
		{
			//throw runtime_error("Could not read mm_offset");
			_sm->Unlock();
			return maps;
		}

		addr_t mmap = 0;
		if (vmi_read_64_va(vmi, mm_struct_ptr, 0, &mmap) != VMI_SUCCESS)
		{
			//throw runtime_error("Could not read mm_struct_ptr");
			_sm->Unlock();
			return maps;
		}

		addr_t vm_area_ptr = mmap;

		do
		{
			vm_area mmap;
			addr_t vm_file = 0;

			// http://lxr.free-electrons.com/source/include/linux/mm_types.h?v=3.16#L345
			vmi_read_64_va(vmi, vm_area_ptr, 0, &mmap.start);
			vmi_read_64_va(vmi, vm_area_ptr+_vm_end_offset, 0, &mmap.end);

			if (vmi_read_64_va(vmi, vm_area_ptr+_vm_flags_offset, 0, &mmap.flags) == VMI_FAILURE)
			{
				throw runtime_error("Could not read page flags");
			}
			else
			{
				mmap.access = "";

				if((mmap.flags & VM_READ) == VM_READ)
					mmap.access += "r";
				if((mmap.flags & VM_WRITE) == VM_WRITE)
					mmap.access += "w";
				if((mmap.flags & VM_EXEC) == VM_EXEC)
					mmap.access += "x";
			}
			
			vmi_read_64_va(vmi, vm_area_ptr+_vm_pgoff_offset, 0, &mmap.pg_off);
			if (vmi_read_64_va(vmi, vm_area_ptr+_vm_file_offset, 0, &vm_file) == VMI_FAILURE)
			{
				throw runtime_error("Could not read vm_file");
			}

			if(vm_file == 0)
			{
				mmap.path = string("");
			}
			else
			{
				mmap.path = string(d_path((addr_t)(vm_file + _f_path_offset), vmi));
			}

			if (vmi_read_64_va(vmi, vm_area_ptr+_vm_next_offset, 0, &vm_area_ptr) != VMI_SUCCESS)
			{
				throw runtime_error("Could not read vm_area_ptr");
			}

			maps.push_back(mmap);
		}
		while (vm_area_ptr != 0);

		_sm->Unlock();
		return maps;
	}

	bool SyscallProcessor::callback(const Event* ev, void* data)
	{
		SystemMonitor* sm = _lvm->GetSystemMonitor();
		vmi_instance_t vmi = sm->Lock();

		bool ret = _lvm->ProcessSyscall((SyscallBreakpoint*) ev, data, vmi);

		sm->Unlock();
		return ret;
	}

	bool CodeInjectionProcessorInt3::callback(const Event* ev, void* data)
	{
		SystemMonitor* sm = _lvm->GetSystemMonitor();

		BPEventData* a = (BPEventData*) data;
		if(!a->beforeSingleStep)
			return false;

		vmi_instance_t vmi = sm->Lock();
		bool ret = _lvm->ProcessInt3CodeInjection((ProcessBreakpointEvent*) ev, data, vmi);
		sm->Unlock();

		// cout << "called" << endl;
		return ret;
	}

	bool CodeInjectionProcessorCr3::callback(const Event* ev, void* data)
	{
		SystemMonitor* sm = _lvm->GetSystemMonitor();
		vmi_instance_t vmi = sm->Lock();

		vmi_event_t* a = (vmi_event_t*) data;

		bool s = _lvm->ProcessCR3CodeInjection(vmi, a);

		sm->Unlock();

		// cout << "called" << endl;
		return s;
	}

	struct returnhelper
	{
		int nr; // in
		bool ret_required; // out
	};

	static void ReturnValueRequired(const SyscallEvent* sev, void* data) 
	{
		struct returnhelper* r = (struct returnhelper*)data;
		if (sev->GetNr() == r->nr && sev->WithRet()) 
		{
			r->ret_required = true;
		}
	}

	bool LinuxVM::ProcessSyscall(const SyscallBreakpoint* ev, void* data, vmi_instance_t vmi)
	{
		struct BPEventData* bpd = (struct BPEventData*)data;
		unsigned int vcpu = bpd->vcpu;
		x86_registers_t* regs = &bpd->regs;

#ifdef VMTRACE_DEBUG
		cout << "Process syscall : " << ev->GetName() << " before single step ? " << bpd->beforeSingleStep << endl;
#endif

		if(bpd->beforeSingleStep)
		{
			return false;
		}
		else
		{
			if(ev->GetNr() != 56 && ev->GetType() == BEFORE_CALL)
			{
				addr_t rip_pa = 0;
				vmi_translate_kv2p(vmi,regs->rip, &rip_pa);
				if(_sm->IsExcludeAddress(rip_pa))
					return false;
			}
		}

		if (ev->GetType() == BEFORE_CALL)
		{
			struct returnhelper rh;
			rh.nr = ev->GetNr();
			rh.ret_required = false; 

			if (ev->Is32bit())
			{
				_SyscallEvents32.ForEach(ReturnValueRequired, (void*)&rh);
			}
			else
			{
				_SyscallEvents64.ForEach(ReturnValueRequired, (void*)&rh);
			}

			SyscallBasic* s = nullptr;

			if(ev->ProcessJson())
			{
				s = new SyscallJson(vmi, vcpu, true, ev->Is32bit(), rh.ret_required, regs);
				// (static_cast<SyscallJson*>(s))->PreProcess(*this, ev->GetNr(), vmi);
			}
			else
			{
				s = new SyscallBasic(vmi, vcpu, true, ev->Is32bit(), rh.ret_required, regs);
				// s->PreProcess(*this, ev->GetNr(), vmi);
			}

			s->PreProcess(*this, ev->GetNr(), vmi);

			if (rh.nr != 59 && (rh.ret_required || s->PageFault())) 
			{
				addr_t paddr = 0;
				vmi_pagetable_lookup(vmi, s->GetDtb(), s->GetRip(), &paddr);
				
				SyscallBreakpoint* bp2 =
					new SyscallBreakpoint(paddr, _syscallProc, ev->GetNr(), AFTER_CALL, ev->Is32bit(), ev->ProcessJson(), s);
				
				_sm->GetBPM()->InsertBreakpoint(bp2);
			} 
			else 
			{
				if (ev->Is32bit()) 
				{
					_SyscallEvents32.Call(ev->GetNr(), (void*)s);
				} 
				else 
				{
					_SyscallEvents64.Call(ev->GetNr(), (void*)s);
				}

				delete s;
			}
		}
		else if (ev->GetType() == AFTER_CALL)
		{
			SyscallBasic* s = ev->GetSyscall();
			//if fork returns 0 we wait for the second BP in order to get the child
			if (regs->cr3 != s->GetDtb() && s->GetNr() == 56)
			{
				return true;
			}
			if (regs->cr3 != s->GetDtb())
			{
				return false;
			}

			if (s->PageFault())
			{
				(static_cast<SyscallJson*>(s))->PreProcess(*this, ev->GetNr(), vmi);
			}

			s->PostProcess(*this, vcpu, vmi, regs);

			// if(!ev->ProcessJson())
			// {
			// 	s->PostProcess(*this, vcpu, vmi, regs);
			// }
			// else
			// {
			// 	(static_cast<SyscallJson*>(s))->PostProcess(*this, vcpu, vmi, regs);
			// }

			if(ev->Is32bit())
			{
				_SyscallEvents32.Call(ev->GetNr(), (void*)s);
			}
			else
			{
				_SyscallEvents64.Call(ev->GetNr(), (void*)s);
			}

			delete s;
			delete ev;
			return true;
		}

		return false;
	}

	status_t LinuxVM::DeRegisterSyscall(SyscallEvent& ev)
	{
		if (ev.Is32bit())
		{
			if (_SyscallEvents32.GetCount(ev.GetNr()) == 1)
			{
				// Remove Breakpoint for this syscall
				std::map<int, const SyscallBreakpoint>::iterator it;
				if ((it = _Syscallbps32.find(ev.GetNr())) != _Syscallbps32.end())
				{
					_sm->GetBPM()->RemoveBreakpoint(&it->second);
					_Syscallbps32.erase(ev.GetNr());
				}
			}
			_SyscallEvents32.DeRegisterEvent(ev.GetNr(), &ev);
		}
		else 
		{
			if (_SyscallEvents64.GetCount(ev.GetNr()) == 1)
			{
				// Remove Breakpoint for this syscall
				map<int, const SyscallBreakpoint>::iterator it;
				if ((it = _Syscallbps64.find(ev.GetNr())) != _Syscallbps64.end())
				{
					_sm->GetBPM()->RemoveBreakpoint(&it->second);
					_Syscallbps64.erase(ev.GetNr());
				}
			}
			_SyscallEvents64.DeRegisterEvent(ev.GetNr(), &ev);
		}

		return VMI_SUCCESS;
	}

	status_t LinuxVM::RegisterSyscall(SyscallEvent& ev)
	{
		SyscallType type;
		addr_t bpaddr = 0;

		if (ev.Is32bit())
		{
			if(_SyscallEvents32.GetCount(ev.GetNr()) != 0)
			{
				return VMI_FAILURE;
			}
		}
		else
		{
			if (_SyscallEvents64.GetCount(ev.GetNr()) != 0)
			{
				return VMI_FAILURE;
			}
		}

		vmi_instance_t vmi = _sm->Lock();

		if (ev.GetNr() == -1)
		{
			_sm->Unlock();
			return VMI_FAILURE;
		}
		else
		{
			addr_t syscall_addr_pa = GetSyscallAddrPA(ev.GetNr(), ev.Is32bit(), vmi);
			if (syscall_addr_pa == 0)
			{
				cerr << "something went wrong" << endl;
				_sm->Unlock();
				return VMI_FAILURE;
			}

			bpaddr = syscall_addr_pa;
			type = BEFORE_CALL;
		}

		SyscallBreakpoint e(bpaddr, _syscallProc, ev.GetNr(), type, ev.Is32bit(), ev.ProcessJson());

		if (ev.Is32bit())
		{
			pair<std::map<int, const SyscallBreakpoint>::iterator, bool> p =
				_Syscallbps32.insert(std::pair<int, const SyscallBreakpoint>(ev.GetNr(), e));

			_sm->GetBPM()->InsertBreakpoint(&(p.first->second));
			_SyscallEvents32.RegisterEvent(ev.GetNr(), &ev);
		}
		else
		{
			pair<std::map<int, const SyscallBreakpoint>::iterator, bool> p =
				_Syscallbps64.insert(pair<int, const SyscallBreakpoint>(ev.GetNr(), e));

			_sm->GetBPM()->InsertBreakpoint(&(p.first->second));
			_SyscallEvents64.RegisterEvent(ev.GetNr(), &ev);
		}

		_sm->Unlock();

		return VMI_SUCCESS;
	}

	addr_t LinuxVM::GetSyscallAddrPA(unsigned int syscall_nr, bool is32bit, vmi_instance_t vmi) 
	{
		addr_t syscall_addr_va = GetSyscallAddrVA(syscall_nr, is32bit, vmi);
		if (syscall_addr_va == 0)
			return 0;

		addr_t syscall_addr_pa = 0;
		vmi_translate_kv2p(vmi, syscall_addr_va, &syscall_addr_pa);

		if (syscall_addr_pa == 0)
			return 0;

		return syscall_addr_pa;
	}

	addr_t LinuxVM::GetSyscallAddrVA(unsigned int syscall_nr, bool is32bit, vmi_instance_t vmi) 
	{
		addr_t sys_call_table =0;
		addr_t func;

		if (is32bit)
		{
			vmi_translate_ksym2v(vmi, "ia32_sys_call_table", &sys_call_table);
		}
		else
		{
			vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table);
		}

		vmi_translate_kv2p(vmi, sys_call_table, &sys_call_table);



		if ( vmi_read_64_pa(vmi, sys_call_table + 8 * syscall_nr, &func) != VMI_SUCCESS) 
		{
			cerr << "Could not read system call table" << endl;
			return 0;
		}

		return func;
	}

	addr_t LinuxVM::GetSymbolAddrVa(const string binaryPath, const Process& p, const string symbolName, const bool onlyFunctions)
	{
		addr_t va = 0;
		int len = 0;

		if(binaryPath.compare(_binaryPathTemp) != 0)
		{
			_binaryMap = _eh->map_file(binaryPath.c_str(), 0, &len);
			_binaryPathTemp = binaryPath;
		}

		const auto offset = _eh->elf_get_symbol_addr(_binaryMap, ".symtab", symbolName.c_str(), onlyFunctions);
		const auto maps = GetMMaps(p);

		for (const auto& entry : maps)
		{
			if (onlyFunctions && !(entry.flags & 0x4))
				continue;

			if (entry.path.find(p.GetName()) != string::npos)
			{
				va = entry.start + offset;
				break;
			}
		}
	
		return va;
	}

	addr_t LinuxVM::GetSymbolAddrPa(const string binaryPath, const Process& p, const string symbolName, const bool onlyFunctions)
	{
		addr_t va = GetSymbolAddrVa(binaryPath, p, symbolName, onlyFunctions);
		
		if(va == 0)
		{
			return 0;
		}

		addr_t pa = 0;

		vmi_instance_t vmi = _sm->Lock();

		vmi_translate_uv2p(vmi, va, p.GetPid(), &pa);

		_sm->Unlock();

		return pa;
	}

	addr_t LinuxVM::GetSymbolAddrVa(const uint8_t* binary, const Process& p, const std::string path, const std::string symbolName, const bool onlyFunctions)
	{
		return  _eh->elf_get_symbol_addr(const_cast<uint8_t*>(binary),
				".symtab", symbolName.c_str(), onlyFunctions);
	}

	bool LinuxVM::ProcessInt3CodeInjection(const ProcessBreakpointEvent* ev, void* data, vmi_instance_t vmi)
	{
		BPEventData* a = (BPEventData*) data;
		
		//BP 1 hit -- most likely for page fault
		vector<CodeInjection>::iterator it2 = find_if(_code_injections.begin(), _code_injections.end(), (boost::bind(&CodeInjection::breakpoint_pa1, _1) == ev->GetAddr()));
		if (it2 != _code_injections.end())
		{
			//page fault, we recover
			if((*it2).type == PAGE_FAULT)
			{
				auto end = std::chrono::high_resolution_clock::now();
				auto dur = end - (*it2).start1;
				auto ms = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
				// UNUSED(ms);
				cout << "it took : " << dec << ms << " for : " << dec << _total_address_per_inst << endl;


#ifdef VMTRACE_DEBUG
				cout << "Page Fault BP hit" << endl;
#endif

#ifdef VMTRACE_DEBUG
				cout << "\t\t\tPut back everything in original" << endl;
#endif

				vmi_set_vcpureg(vmi, (*it2).entry_addr, RIP, a->vcpu);

				addr_t temp = 0;
				vector<addr_t>::iterator it = (*it2).target_addrs.begin();
				uint64_t count = 0;
				uint64_t count1 = 0;
				while(it != (*it2).target_addrs.end())
				{
					if(vmi_translate_uv2p(vmi, (*it), (*it2).target_pid, &temp) == VMI_SUCCESS)
					{
						(*it2).result_addrs.push_back(make_pair((*it), temp));

						it = (*it2).target_addrs.erase(it);

						count++;
					}
					else
					{
						count1++;
						++it;
					}
				}

				if(count > _total_address_per_inst)
				{
					cout << "more than target : " << dec << count << endl;
				}
				else
				{
					cout << "less than target : " << dec << count << endl;
				}

				addr_t* addrs = new addr_t[_total_address_per_inst];
				if((*it2).target_addrs.size() < _total_address_per_inst && (*it2).target_addrs.size() != 0)
				{
					uint32_t i = 0;
					for(; i < (*it2).target_addrs.size() ; i++)
					{
						addrs[i] = (*it2).target_addrs.at(i);
					}

					for(; i < _total_address_per_inst ; i++)
					{
						addrs[i] = (*it2).target_addrs.at(0);
					}
				}
				else if((*it2).target_addrs.size() != 0)
				{
					for(uint32_t i = 0 ; i < _total_address_per_inst ; i++)
					{
						addrs[i] = (*it2).target_addrs.at(i);
					}
				}

				if((*it2).target_addrs.size() != 0)
				{
					int start2 = 3;
					for(uint64_t i = 0 ; i < _total_address_per_inst ; i++)
					{
						memcpy((*it2).inject_code + start2, &addrs[i], sizeof(addr_t));
						start2 = start2 + 13;
					}
				}

				delete[] addrs;

				if((*it2).target_addrs.size() == 0) // all done, recover
				{
					vmi_write_va(vmi, (*it2).entry_addr, (*it2).target_pid, (*it2).instr_size, (*it2).saved_code, NULL);

					delete (*it2).bp1;
					delete[] (*it2).saved_code;
					delete[] (*it2).inject_code;

					CodeInjection ci = *it2;
					(*it2).evl->callback(ev, &ci);

					_code_injections.erase(it2);

					if(_code_injections.size() == 0)
					{
						_sm->GetRM()->RemoveRegisterEvent(_process_change);
					}

					return true;
				}
				else // not done, reinject with new target address
				{
					(*it2).start1 = std::chrono::high_resolution_clock::now();
					vmi_write_va(vmi, (*it2).entry_addr, (*it2).target_pid, (*it2).instr_size, (*it2).inject_code, NULL);
					return false;
				}
			}

			return false;
		}

		// BP 2 hit most likely for child of vfork -- inject for exec
		it2 = find_if(_code_injections.begin(), _code_injections.end(), (boost::bind(&CodeInjection::breakpoint_pa2, _1) == ev->GetAddr()));
		if (it2 != _code_injections.end())
		{

#ifdef VMTRACE_DEBUG
			cout << "bp 2 hit fork exec" << endl;
#endif

			//int execve(const char *filename, char *const argv[], char *const envp[]);
			//int execve("/bin/bash", {"/bin/bash", "-c", "<command>", 0}, envp[]);

			reg_t rsp = a->regs.rsp;
			addr_t orig_addr = rsp;
			addr_t param1_addr = orig_addr;
			size_t len = strlen(bin) + 1;
			param1_addr -= len;
			//align
			param1_addr &= ~0x7;
			size_t buf_len = orig_addr - param1_addr;
			if(vmi_write_va(vmi, param1_addr, (*it2).target_pid, buf_len, (void*)bin, NULL) == VMI_FAILURE)
			{
				cerr << "could not write the exec filename + argv 1" << endl;
			}
			vmi_set_vcpureg(vmi, param1_addr, RDI, a->vcpu); //filename

#ifdef VMTRACE_DEBUG
			cout << "exec filename + argv 1 addr : " << hex << param1_addr << endl;
#endif

			len = strlen(param1) + 1;
			orig_addr = param1_addr;
			addr_t param2_addr = orig_addr;
			param2_addr -= len;
			//align
			param2_addr &= ~0x7;
			buf_len = orig_addr - param2_addr;
			if(vmi_write_va(vmi, param2_addr, (*it2).target_pid, buf_len, (void*)param1, NULL) == VMI_FAILURE)
			{
				cerr << "could not write the exec argv 2" << endl;
			}

#ifdef VMTRACE_DEBUG
			cout << "exec argv 2 addr : " << hex << param2_addr << endl;
#endif

			len = strlen(((*it2).command).c_str()) + 1;
			orig_addr = param2_addr;
			addr_t param3_addr = orig_addr;
			param3_addr -= len;
			//align
			param3_addr &= ~0x7;
			buf_len = orig_addr - param3_addr;
			if(vmi_write_va(vmi, param3_addr, (*it2).target_pid, buf_len, (void*)((*it2).command).c_str(), NULL) == VMI_FAILURE)
			{
				cerr << "could not write the exec argv 3" << endl;
			}

#ifdef VMTRACE_DEBUG
			cout << "exec argv 3 addr : " << hex << param3_addr << endl;
#endif

			uint64_t null64 = 0;
			len = 8;
			orig_addr = param3_addr;
			addr_t param4_addr = orig_addr;
			param4_addr -= len;
			//align
			param4_addr &= ~0x7;
			vmi_write_64_va(vmi, param4_addr, (*it2).target_pid, &null64);
			vmi_set_vcpureg(vmi, param4_addr, RDX, a->vcpu); //envp

			// populate for argv[]
			len = 32; //8
			addr_t addr = param3_addr;
			addr -= len;
			addr &= ~0x7;

			vmi_write_64_va(vmi, addr, (*it2).target_pid, &param1_addr);
			vmi_write_64_va(vmi, (addr+8), (*it2).target_pid, &param2_addr);
			vmi_write_64_va(vmi, (addr+16), (*it2).target_pid, &param3_addr);
			vmi_write_64_va(vmi, (addr+24), (*it2).target_pid, &null64);
			
			vmi_set_vcpureg(vmi, addr, RSI, a->vcpu); //argv

#ifdef VMTRACE_DEBUG
			cout << "argv : " << hex << addr << ", " << (addr+8) << ", " << (addr+16) << ", " << (addr+24) << endl;
#endif

			addr_t rip = a->regs.rip;

			(*it2).regs.rsp = a->regs.rsp;
			(*it2).breakpoint_pa2 = 0;

			vmi_set_vcpureg(vmi, rip + 1, RIP, a->vcpu);

			return false;
		}

		// BP 2 hit most likely for parent of vfork -- recover
		it2 = find_if(_code_injections.begin(), _code_injections.end(), (boost::bind(&CodeInjection::breakpoint_pa3, _1) == ev->GetAddr()));
		if (it2 != _code_injections.end())
		{

#ifdef VMTRACE_DEBUG
			cout << "bp 3 hit fork exec" << endl;
#endif

			CodeInjection ci = *it2;
			vmi_read_64_va(vmi, a->regs.rsp, it2->target_pid, (uint64_t*) &ci.child_pid);
		
			vmi_set_vcpureg(vmi, a->regs.rsp + 8, RSP, a->vcpu);
			vmi_set_vcpureg(vmi, (*it2).breakpoint1, RIP, a->vcpu);

			vmi_write_va(vmi, (*it2).breakpoint1, (*it2).target_pid, (*it2).instr_size, (*it2).saved_code, NULL);
			
			(*it2).evl->callback(ev, &ci);

			delete (*it2).bp1;
			delete[] (*it2).saved_code;

			_code_injections.erase(it2);

			if(_code_injections.size() == 0)
			{
				_sm->GetRM()->RemoveRegisterEvent(_process_change);
			}

			return true;
		}

		return true;
	}

	bool LinuxVM::ProcessCR3CodeInjection(vmi_instance_t vmi, vmi_event_t *event)
	{
		// vmi_pid_t pid = 0;
		// vmi_dtb_to_pid(vmi, event->reg_event.value, &pid);

		CodeInjectionType type = NOPE;

		vector<CodeInjection>::iterator it3 = find_if(_code_injections.begin(), _code_injections.end(), (boost::bind(&CodeInjection::target_dtb, _1) == event->reg_event.value));
		if (it3 != _code_injections.end())
		{
			type = (*it3).type;
		}

		if(type == NOPE)
		{
			return false;
		}
		else if(type == PAGE_FAULT || type == FORK_EXEC)
		{
			vmi_pid_t pid = (*it3).target_pid;
			
			// needed if there are more than 2
			vmi_v2pcache_flush(vmi, ~0ull);

			addr_t task = (*it3).task_struct;

			//https://stackoverflow.com/questions/25253231/context-of-linux-kernel-threads
			addr_t sp0 = 0;
			vmi_read_addr_va(vmi, task + _thread_struct_offset + _sp0_offset, 0, &sp0);

			/* README
			* arch/x86/include/asm/processor.h  - line 927
			*
			* The macro #define task_pt_regs(tsk)	((struct pt_regs *)(tsk)->thread.sp0 - 1)
			* returns a pointer to the struct pt_regs of the given task. However, be aware
			* of the semantic of the above macro (c pointer arithmetic), it subtracts
			* sizeof(struct pt_regs) = 168 (0xa8) rather than -1 from tsk.thread.sp0.
			*
			*/
			addr_t ptr_pt_regs = (sp0-0xa8);
			addr_t pt_regs_ip;

			//find the next instruction address that about to be executed
			vmi_read_addr_va(vmi, ptr_pt_regs + _ip_on_pt_regs_offset, 0, &pt_regs_ip);

			if(type == PAGE_FAULT)
			{
				(*it3).entry_addr = pt_regs_ip;

				(*it3).saved_code = new char[(*it3).instr_size];
				(*it3).breakpoint1 = pt_regs_ip + (*it3).instr_size;

				addr_t breakpoint_pa;
				vmi_translate_uv2p(vmi, (*it3).breakpoint1, pid, &breakpoint_pa);
				(*it3).breakpoint_pa1 = breakpoint_pa;
				(*it3).breakpoint_pa2 = 0;
				(*it3).breakpoint_pa3 = 0;

#ifdef VMTRACE_DEBUG
				cout << "\t(BP) VA : " << hex << (*it3).breakpoint1 << " PA : " << (*it3).breakpoint_pa1 << endl;
#endif

				if((*it3).breakpoint_pa1 == 0)
				{
					delete[] (*it3).saved_code;
					delete[] (*it3).inject_code;

					_code_injections.erase(it3);
					cerr << "Page fault BP PA = " << (*it3).breakpoint_pa1 << endl;

					return true;
				}

				(*it3).bp1 = new ProcessBreakpointEvent("Page Fault", 0, breakpoint_pa, _code_injection_proc_int3);
				_sm->GetBPM()->InsertBreakpoint((*it3).bp1);

				//read the original instruction and then inject the new payload
				vmi_read_va(vmi, (*it3).entry_addr, pid, (*it3).instr_size, (*it3).saved_code, NULL);
				vmi_write_va(vmi, (*it3).entry_addr, pid, (*it3).instr_size, (*it3).inject_code, NULL);

#ifdef VMTRACE_DEBUG
				addr_t code_paddr = 0;
				vmi_translate_uv2p(vmi, (*it3).entry_addr, pid, &code_paddr);
				
				cout << "\tWrite the injected instruction to PA : " << hex << code_paddr << endl;
				cout << "code" << endl;
				cout << hexdumptostring((*it3).inject_code, (*it3).instr_size) << endl;
				
				cout << "old inst" << endl;
				cout << hexdumptostring((*it3).saved_code, (*it3).instr_size) << endl;
				
				cout << "new inst" << endl;
				char* tmp = new char[(*it3).instr_size];
				vmi_read_va(vmi, (*it3).entry_addr, pid, (*it3).instr_size, tmp, NULL);
				cout << hexdumptostring(tmp, (*it3).instr_size) << endl;

				delete[] tmp;
#endif
			}
			else if(type == FORK_EXEC)
			{
				(*it3).saved_code = new char[(*it3).instr_size];

				(*it3).breakpoint1 = pt_regs_ip;
				addr_t breakpoint_pa = 0;
				vmi_translate_uv2p(vmi, (*it3).breakpoint1, pid, &breakpoint_pa);
				(*it3).breakpoint_pa1 = breakpoint_pa;
				
				(*it3).breakpoint2 = (*it3).breakpoint1 + 14;
				vmi_translate_uv2p(vmi, (*it3).breakpoint2, pid, &breakpoint_pa);
				(*it3).breakpoint_pa2 = breakpoint_pa;

				(*it3).breakpoint3 = (*it3).breakpoint3;
				(*it3).breakpoint_pa3 = (*it3).breakpoint_pa2;

#ifdef VMTRACE_DEBUG
				cout << hex << "VFORK EXEC BP 1 : " << (*it3).breakpoint1 << " = " << (*it3).breakpoint_pa1 << endl;
				cout << hex << "VFORK EXEC BP 2 : " << (*it3).breakpoint2 << " = " << (*it3).breakpoint_pa2 << endl;
#endif

				if((*it3).breakpoint_pa1 == 0 || (*it3).breakpoint_pa2 == 0)
				{
					delete[] (*it3).saved_code;

					_code_injections.erase(it3);
					cerr << "fail PA - VFORK_EXEC" << endl;

					return true;
				}

				if(vmi_read_va(vmi, (*it3).breakpoint1, pid, (*it3).instr_size, (*it3).saved_code, NULL) == VMI_FAILURE)
				{
					_code_injections.erase(it3);
					cerr << "unable to read original instruction - VFORK_EXEC" << endl;

					return true;
				}

				// (*it3).bp1 = new ProcessBreakpointEvent("VFORK EXEC 1", 0, (*it3).breakpoint_pa1, _code_injection_proc_int3);
				// _sm->GetBPM()->InsertBreakpoint((*it3).bp1);

				(*it3).bp1 = new ProcessBreakpointEvent("VFORK EXEC 1", 0, (*it3).breakpoint_pa2, _code_injection_proc_int3);
				_sm->GetBPM()->InsertBreakpoint((*it3).bp1);

				vmi_write_va(vmi, (*it3).breakpoint1, pid, (*it3).instr_size, code_syscall_vfork_exec, NULL);
				// vmi_write_va(vmi, (*it3).breakpoint2 + 1, pid, 2, code_syscall, NULL);

				// char* tmp = new char[5];
				// vmi_read_va(vmi, (*it3).breakpoint1 + 1, pid, 5, tmp, NULL);
				// cout << hexdumptostring(tmp, 5) << endl;

				// delete[] tmp;
#ifdef VMTRACE_DEBUG
				addr_t code_paddr = 0;
				vmi_translate_uv2p(vmi, (*it3).breakpoint1, pid, &code_paddr);

				cout << "\tWrite the injected instruction to PA : " << hex << code_paddr << endl;
				cout << "code" << endl;
				cout << hexdumptostring(code_syscall_vfork_exec, (*it3).instr_size) << endl;

				cout << "old inst" << endl;
				cout << hexdumptostring((*it3).saved_code, (*it3).instr_size) << endl;

				cout << "new inst" << endl;
				char* tmp = new char[(*it3).instr_size];
				vmi_read_va(vmi, (*it3).breakpoint1, pid, (*it3).instr_size, tmp, NULL);
				cout << hexdumptostring(tmp, (*it3).instr_size) << endl;

				delete[] tmp;
#endif
			}

			(*it3).start1 = std::chrono::high_resolution_clock::now();

			return true;
		}
		else
		{
			return false;
		}
	}

	// populate address to be page faulted
	void LinuxVM::PopulatePageFaultAdress(const vmi_pid_t pid, const addr_t target, EventListener* evl)
	{
		vmi_instance_t vmi = _sm->Lock();

		addr_t temp;
		if(vmi_read_addr_va(vmi, target, pid, &temp) == VMI_SUCCESS)
		{
			cerr << "No page fault needed" << endl;
			_sm->Unlock();
			return;
		}

		bool processFound = false;
		bool areaFound = false;

		addr_t target_dtb = 0;
		addr_t task_struct = 0;
		uint64_t total_page = 0;

		vector<Process> processes = GetProcessList();
		for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
		{
			if((*it).GetPid() == pid)
			{
				processFound = true;

				target_dtb = (*it).GetDtb();
				task_struct = (*it).GetTaskStruct();

				vector<vm_area> maps = GetMMaps(*it);
				for(vector<vm_area>::iterator it2 = maps.begin() ; it2 != maps.end(); ++it2)
				{
					if ((*it2).start <= target && target < (*it2).end)
					{
						areaFound = true;
						break;
					}
				}

				pair<addr_t, addr_t> text_section = GetCodeArea((*it).GetPid());
				addr_t begin = text_section.first >> 12;
				begin = begin << 12;

				addr_t end = text_section.second >> 12;
				end++;
				end = end << 12;

				total_page = (end - begin)/4096;

				break;
			}
		}

		if(!processFound)
		{
			cerr << "No process found for code injection" << endl;
			_sm->Unlock();
			return;
		}

		if(!areaFound)
		{
			cerr << "Address to be page fault not inside the mmaps" << endl;
			_sm->Unlock();
			return;
		}

		vector<CodeInjection>::iterator it2 = find_if(_code_injections.begin(), _code_injections.end(), (boost::bind(&CodeInjection::target_pid, _1) == pid));
		if (it2 != _code_injections.end())
		{
			(*it2).target_addrs.push_back(target);
			_sm->Unlock();
			return;
		}
		else
		{
			CodeInjection ci;
			ci.type = PAGE_FAULT;
			ci.target_pid = pid;
			ci.target_addrs.push_back(target);
			ci.evl = evl;
			ci.target_dtb = target_dtb;
			ci.task_struct = task_struct;
			ci.total_page_text = total_page;
			ci.start = std::chrono::high_resolution_clock::now();

			_code_injections.push_back(ci);
		}

		_sm->Unlock();
	}

	// execute the page fault - continuation of PopulatePageFaultAdress
	status_t LinuxVM::InvokePageFault(uint64_t total_address_per_inst)
	{

#ifdef VMTRACE_DEBUG
		cout << "invoke page fault begin" << endl;
#endif

		if(_sm->GetBPM()->GetType() != INTTHREE)
		{
			cerr << "Current BPM not supported" << endl;
			return VMI_FAILURE;
		}

		if(_sm->GetRM() == nullptr)
		{
			cerr << "RegisterMechanism is required to do code injection" << endl;
			return VMI_FAILURE;
		}

		if(total_address_per_inst != 0)
		{
			_total_address_per_inst = total_address_per_inst;
		}

		for(vector<CodeInjection>::iterator it = _code_injections.begin() ; it != _code_injections.end(); ++it)
		{
			while(((*it).total_page_text * 4096) < (_total_address_per_inst * 15))
			{
				_total_address_per_inst--;
			}

			uint32_t new_inst_length = sizeof(push_rax) - 1 + (_total_address_per_inst * (sizeof(mov_rax_addr) - 1)) + sizeof(pop_rax) - 1;
			(*it).inject_code = new char[new_inst_length];
			(*it).instr_size = new_inst_length;

			addr_t* addrs = new addr_t[_total_address_per_inst];
			if((*it).target_addrs.size() < _total_address_per_inst && (*it).target_addrs.size() != 0)
			{
				uint32_t i = 0;
				for(; i < (*it).target_addrs.size() ; i++)
				{
					addrs[i] = (*it).target_addrs.at(i);
				}

				for(; i < _total_address_per_inst ; i++)
				{
					addrs[i] = (*it).target_addrs.at(0);
				}
			}
			else if((*it).target_addrs.size() != 0)
			{
				for(uint32_t i = 0 ; i < _total_address_per_inst ; i++)
				{
					addrs[i] = (*it).target_addrs.at(i);
				}
			}

			if((*it).target_addrs.size() != 0)
			{
				memcpy((*it).inject_code, &push_rax, 1);
				int start1 = 1;
				int start2 = 3;
				for(uint64_t i = 0 ; i < _total_address_per_inst ; i++)
				{
					memcpy((*it).inject_code + start1, &mov_rax_addr, sizeof(mov_rax_addr) - 1);
					memcpy((*it).inject_code + start2, &addrs[i], sizeof(addr_t));
					start1 = start1 + 13;
					start2 = start2 + 13;
				}
				memcpy((*it).inject_code + new_inst_length - 1, &pop_rax, 1);
			}

			delete[] addrs;
		}


		if(_process_change == nullptr)
		{
			_process_change = new ProcessChangeEvent(_code_injection_proc_cr3);
		}

		_sm->GetRM()->InsertRegisterEvent(_process_change);

		return VMI_SUCCESS;
	}

	status_t LinuxVM::InvokeCommand(const vmi_pid_t pid, string command, EventListener* evl)
	{

#ifdef VMTRACE_DEBUG
		cout << "invoke code injection begin" << endl;
#endif

		if(_sm->GetBPM()->GetType() != INTTHREE)
		{
			cerr << "Current BPM not supported" << endl;
			return VMI_FAILURE;
		}

		if(_sm->GetRM() == nullptr)
		{
			cerr << "RegisterMechanism is required to do code injection" << endl;
			return VMI_FAILURE;
		}

		bool processFound = false;

		addr_t target_dtb = 0;
		addr_t task_struct = 0;

		vector<Process> processes = GetProcessList();
		for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
		{
			if((*it).GetPid() == pid)
			{
				processFound = true;

				target_dtb = (*it).GetDtb();
				task_struct = (*it).GetTaskStruct();
			}
		}

		if(!processFound)
		{
			cerr << "No process found for code injection" << endl;
			_sm->Unlock();
			return VMI_FAILURE;
		}

		CodeInjection ci;
		ci.type = FORK_EXEC;
		ci.target_pid = pid;
		ci.evl = evl;
		ci.target_dtb = target_dtb;
		ci.task_struct = task_struct;
		ci.start = std::chrono::high_resolution_clock::now();

		uint32_t new_inst_length = sizeof(code_syscall_vfork_exec) - 1;
		ci.instr_size = new_inst_length;
		ci.command = command;

		_code_injections.push_back(ci);

		if(_process_change == nullptr)
			_process_change = new ProcessChangeEvent(_code_injection_proc_cr3);

		_sm->GetRM()->InsertRegisterEvent(_process_change);

#ifdef VMTRACE_DEBUG
		cout << "Injecting proc change event" << endl;
#endif

		return VMI_SUCCESS;
	}

	Process LinuxVM::InjectELF(const Process& p, std::vector<uint8_t>& executable)
	{
		// TODO: we want to use smart pointers everywhere,
		// so transition to enable_shared_from_this
		// soon (TM). this is just a dirty hack so we can call
		// into the elf injector part.
		std::shared_ptr<SystemMonitor> sm(std::shared_ptr<SystemMonitor>{}, _sm);
		std::shared_ptr<LinuxVM> vm(std::shared_ptr<LinuxVM>{}, this);
		std::shared_ptr<std::vector<uint8_t>> exe(
				std::shared_ptr<std::vector<uint8_t>>{}, &executable);
		
		// pass it into the wrapping class.
		LinuxELFInjector elf(sm, vm, p);
		return elf.inject_executable(exe);
	}
	
	Process LinuxVM::InjectELF(const Process& p, const std::string executable)
	{
		// read the executable to inject from disk.
		std::ifstream file(executable, std::ios::binary);
		const auto exe = std::make_shared<std::vector<uint8_t>>(
			std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
		return InjectELF(p, *exe);
	}
	
	void LinuxVM::ExtractFile(const Process& p, const std::string file, const std::string out)
	{
		using namespace file_extraction;

		// TODO: we want to use smart pointers everywhere,
		// so transition to enable_shared_from_this
		// soon (TM). this is just a dirty hack so we can call
		// into the file extractor part.
		std::shared_ptr<SystemMonitor> sm(std::shared_ptr<SystemMonitor>{}, _sm);
		std::shared_ptr<LinuxVM> vm(std::shared_ptr<LinuxVM>{}, this);
		
		// prepare extraction agent and setup communication.
		std::vector<uint8_t> agent;
		agent.assign(linux_agent_start, linux_agent_end);
		const auto child = InjectELF(p, agent);
		LinuxFileExtractor extractor(sm, vm, child, agent);

		// request the file and dump it onto local filesystem.
		extractor.request_file(file);
		extractor.open_file(out);
		while (!extractor.read_chunk()) { /* nothing */ }
		extractor.close_file();
	}
	
	std::vector<uint8_t> LinuxVM::ExtractFile(const Process& p, const std::string file)
	{
		// TODO: refactor the wrapping class, so that we can pass a base type
		// of stream to write each chunk into. the tmp file solution is mediocre at best.

		// uhm, yeah...
		Crc32 crc{};
		std::srand(std::time(nullptr));
		const auto tmp_file = std::to_string(crc.update(file.c_str(), file.length())
				+ std::rand());
	
		// dump it and read it from tmp storage.
		ExtractFile(p, file, tmp_file);
		std::ifstream f(tmp_file, std::ios::binary);
		const auto out = std::make_unique<std::vector<uint8_t>>(
				std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
		std::remove(tmp_file.c_str());
		return std::move(*out);
	}

	status_t LinuxVM::RegisterProcessChange(ProcessChangeEvent& ev)
	{
		if(_sm->GetRM() == nullptr)
		{
			cerr << "RegisterMechanism is required to do process change" << endl;
			return VMI_FAILURE;
		}

		_sm->GetRM()->InsertRegisterEvent(&ev);
		return VMI_SUCCESS;
	}
	status_t LinuxVM::DeRegisterProcessChange(ProcessChangeEvent& ev)
	{
		if(_sm->GetRM() == nullptr)
		{
			return VMI_FAILURE;
		}
		
		_sm->GetRM()->RemoveRegisterEvent(&ev);
		return VMI_SUCCESS;
	}

	void LinuxVM::Stop()
	{
		vmi_instance_t vmi = _sm->Lock();

		if(_code_injections.size() != 0)
		{
			for(vector<CodeInjection>::iterator it = _code_injections.begin() ; it != _code_injections.end() ;)
			{
				if((*it).type == PAGE_FAULT)
				{
					vmi_write_va(vmi, (*it).entry_addr, (*it).target_pid, (*it).instr_size, (*it).saved_code, NULL);
				}
				else if((*it).type == FORK_EXEC)
				{
					vmi_write_va(vmi, (*it).breakpoint1, (*it).target_pid, (*it).instr_size, (*it).saved_code, NULL);
				}

				it = _code_injections.erase(it);
			}
		}

		if(_sm->GetBPM() != nullptr)
		{
			_sm->GetBPM()->DeInit();
		}
		
		if(_sm->GetRM() != nullptr)
		{
			_sm->GetRM()->DeInit();
		}

		_sm->Unlock();
	//	_sm->Stop();
	}

	status_t LinuxVM::PauseSyscall(SyscallEvent& ev)
	{
		if (ev.Is32bit())
		{
			if (_SyscallEvents32.GetCount(ev.GetNr()) == 1)
			{
				std::map<int, const SyscallBreakpoint>::iterator it;
				if ((it = _Syscallbps32.find(ev.GetNr())) != _Syscallbps32.end())
				{
					return _sm->GetBPM()->TemporaryRemoveBreakpoint(&it->second);
				}
			}
		}
		else 
		{
			if (_SyscallEvents64.GetCount(ev.GetNr()) == 1)
			{
				map<int, const SyscallBreakpoint>::iterator it;
				if ((it = _Syscallbps64.find(ev.GetNr())) != _Syscallbps64.end())
				{
					return _sm->GetBPM()->TemporaryRemoveBreakpoint(&it->second);
				}
			}
		}

		return VMI_FAILURE;
	}

	status_t LinuxVM::ResumeSyscall(SyscallEvent& ev)
	{
		if (ev.Is32bit())
		{
			if (_SyscallEvents32.GetCount(ev.GetNr()) == 1)
			{
				std::map<int, const SyscallBreakpoint>::iterator it;
				if ((it = _Syscallbps32.find(ev.GetNr())) != _Syscallbps32.end())
				{
					return _sm->GetBPM()->ReInsertBreakpoint(&it->second);
				}
			}
		}
		else 
		{
			if (_SyscallEvents64.GetCount(ev.GetNr()) == 1)
			{
				map<int, const SyscallBreakpoint>::iterator it;
				if ((it = _Syscallbps64.find(ev.GetNr())) != _Syscallbps64.end())
				{
					return _sm->GetBPM()->ReInsertBreakpoint(&it->second);
				}
			}
		}

		return VMI_FAILURE;
	}
}

