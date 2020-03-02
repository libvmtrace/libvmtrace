
#ifndef __PROCESS_H_
#define __PROCESS_H_

#include <libvmi/libvmi.h>
#include <string>
#include <vector>
#include <map>

#include <net/NetworkConnection.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include <util/utils.hpp>

namespace libvmtrace
{
	constexpr auto VM_READ = 0x00000001;
	constexpr auto VM_WRITE = 0x00000002;
	constexpr auto VM_EXEC = 0x00000004;
	constexpr auto VMTRACE_PAGE_SIZE = 4096;

	struct vm_area 
	{
		addr_t start, end;
		addr_t flags;
		addr_t pg_off;
		string path;
		string sha256_hash;
		string mmap_data_full;
		string str_hexdump;
		string access;
	};

	class Process 
	{
		public:
			Process(addr_t addr, vmi_pid_t pid, addr_t dtb, const std::string& name, const std::string& path, vmi_pid_t parent_pid) :
					_task_struct(addr),
					_pid(pid),
					_dtb(dtb),
					_name(name),
					_path(path),
					_parent_pid(parent_pid),
					_mmaps(NULL)//,
					//_tcp_connections_(NULL) 
					{ }

			Process(addr_t addr, vmi_pid_t pid, addr_t dtb, const std::string& name, const std::string& path,
					vmi_pid_t parent_pid, int uid, const std::string& pwd) :
					_task_struct(addr),
					_pid(pid),
					_dtb(dtb),
					_name(name),
					_path(path),
					_parent_pid(parent_pid),
					_uid(uid),
					_pwd(pwd),
					_mmaps(NULL)//,
					//tcp_connections_(NULL) 
					{ }

			vmi_pid_t GetPid() const 
			{
				return _pid;
			}

			int GetUid() const 
			{
				return _uid;
			}
			
			std::string GetName() const 
			{ 
				return _name; 
			}

			std::string GetPath() const
			{
				return _path;
			}

			std::string GetPwd() const 
			{ 
				return _pwd; 
			}

			addr_t GetDtb() const 
			{ 
				return _dtb; 
			}

			void SetMMaps(std::vector<struct vm_area>* mmaps) 
			{ 
				_mmaps = mmaps;
			}

			std::vector<struct vm_area>* GetMMaps() 
			{ 
				return _mmaps;
			}

			void SetTCPConnections(std::vector<NetworkConnection*>* conns) 
			{ 
				tcp_connections_ = conns;
			}

			std::vector<NetworkConnection*>* GetTCPConnections() const 
			{
				return tcp_connections_;
			}

			addr_t GetTaskStruct(void) const 
			{ 
				return _task_struct; 
			}

			vmi_pid_t GetParentPid() const 
			{ 
				return _parent_pid; 
			}

			std::map<string, string> GetStringMap();
			std::map<string, int> GetIntMap();
			rapidjson::Value ToJson(rapidjson::Document::AllocatorType& allocator);
			//Json::Object ToMemoryMapsJson();
		 
		protected:
			addr_t _task_struct;
			vmi_pid_t _pid;
			addr_t _dtb;
			const std::string _name;
			const std::string _path;
			vmi_pid_t _parent_pid;
			int _uid;
			const std::string _pwd;
			std::vector<struct vm_area>* _mmaps;
			std::vector<NetworkConnection*>* tcp_connections_;
	};
}

#endif

