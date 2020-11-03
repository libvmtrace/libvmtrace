
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

#include <iostream>
#include <vector>
#include <boost/bind.hpp>
#include <algorithm>
#include <chrono>
#include <fstream>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <ssh_helper/SSHHelper.hpp>

using namespace std;
using namespace spdlog;
using namespace rapidjson;
using namespace libvmtrace;
using namespace libvmtrace::util;
using namespace libvmtrace::net;
using namespace helpers;

std::shared_ptr<SystemMonitor> _sm;
std::shared_ptr<LinuxVM> _linux;
SSHHelper* _sshhelper;
ProcessCache* _pc;
NetMonitor* _nm; // iptables -A FORWARD -i eth0 -p tcp -j NFQUEUE --queue-num 0

string _log_dir = "";
string _sshd_bin_path = "";
string _sshd_path = "";
string _profile = "";
string _ip = "";
int _modify_auth = 0;
int _bp_type = 0;
int _process_change = 0;
vector<string> _processes_list;

vmi_pid_t _sshd_parent_pid = 0;

vector<sshchild> sshchildren;
vector<writefile> writefiles;

SyscallEvent* cloneS;
SyscallEvent* execveS;
// SyscallEvent* openS;
SyscallEvent* closeS;
SyscallEvent* writeS;
SyscallEvent* lseekS;
SyscallEvent* killS;
SyscallEvent* sendToS;
ProcessChangeEvent* process_change;

static bool interrupted = false;
static void close_handler(int sig)
{
	get("console")->warn("Killing saracenia");

	if (sig == SIGSEGV) 
	{
		_linux = nullptr;
		_sm = nullptr;
	}

	interrupted = true;

	_nm->Stop();
}


bool FindSSHDParent();
void FindNewSSHD(vmi_pid_t pid);
void RemoveSSH(vmi_pid_t pid);

class ProcessChangeListener : public EventListener
{
	public:
		ProcessChangeListener(){}
		bool callback(Event* ev, void* data)
		{
			vmi_event_t* a = (vmi_event_t*) data;

			// previous process is the same
			if(a->reg_event.value == a->reg_event.previous)
			{
				return false;
			}

			_sm->Lock();

			try
			{
				const Process& p = _pc->GetProcessFromDtbAndRefreshIf(a->reg_event.value, "bash");

				if(p.GetName() == "sshd")
				{
					_linux->ResumeSyscall(*cloneS);
					_linux->ResumeSyscall(*killS);
				}
				else
				{
					_linux->PauseSyscall(*cloneS);
					_linux->PauseSyscall(*killS);
				}

				if(_process_change == 1) //whitelist
				{
					if(find(_processes_list.begin(), _processes_list.end(), p.GetName()) != _processes_list.end())
					{
						_linux->ResumeSyscall(*writeS);
						_linux->ResumeSyscall(*lseekS);
						_linux->ResumeSyscall(*closeS);
					}
					else
					{
						_linux->PauseSyscall(*writeS);
						_linux->PauseSyscall(*lseekS);
						_linux->PauseSyscall(*closeS);
					}
				}
				else if(_process_change == 2) //blacklist
				{
					if(find(_processes_list.begin(), _processes_list.end(), p.GetName()) != _processes_list.end())
					{
						_linux->PauseSyscall(*writeS);
						_linux->PauseSyscall(*lseekS);
						_linux->PauseSyscall(*closeS);
					}
					else
					{
						_linux->ResumeSyscall(*writeS);
						_linux->ResumeSyscall(*lseekS);
						_linux->ResumeSyscall(*closeS);
					}
				}
			}
			catch(...)
			{

			}

			_sm->Unlock();
			return false;
		}
};
ProcessChangeListener* processChangeListener;

class CloneListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				vmi_instance_t vmi = _sm->Lock();
				UNUSED(vmi);

				SyscallBasic* s = (SyscallBasic*)data;
				addr_t dtb = s->GetDtb();

				//vmi_v2pcache_flush(vmi, ~0ull);
				try
				{
					const Process& p = _pc->GetProcessFromDtb(dtb);
					const vmi_pid_t pid = p.GetPid();
					const vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);

					//get("console")->info("Clone : {0:d} : {1:d}", pid, parent);

					vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
					if (it != sshchildren.end())
					{

					}
					else if(pid == _sshd_parent_pid)
					{
						FindNewSSHD(s->GetRet());
					}
				}
				catch(...)
				{
					cerr << "could not find process CLONE : " << hex << dtb <<  endl;
				}

				_sm->Unlock();
			}
			return false;
		}
};
CloneListener* cloneListener;

class ExecListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				SyscallJson* s = (SyscallJson*)data;

				string json = s->ToJson();
				Document document;
				document.Parse(json.c_str());

				string args = "";
				const Value& a = document["args"];
				for (SizeType i = 0; i < a.Size(); i++)
				{
					string tmp(a[i].GetString());
					args = args + "," +tmp;
				}

				string path(document["path"].GetString());

				const Process& p = _pc->GetProcessFromDtb(s->GetDtb());
				vmi_pid_t pid = p.GetPid();

				vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);
				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					get(to_string((*it).pid)+"exec")->info("Exec - pid : {0:d} [{1}]\nargs : {2}\n", s->GetPid(), path, args);
					get(to_string((*it).pid)+"exec")->flush();
				}
				else
				{
					get("parent")->info("Exec without SSHD - pid : {0:d} [{1}]\nargs : {2}\n", s->GetPid(), path, args);
					get("parent")->flush();
				}
			}
			return false;
		}
};
ExecListener* execListener;

class KillListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				vmi_instance_t vmi = _sm->Lock();
				UNUSED(vmi);
				
				try
				{
					SyscallBasic* s = (SyscallBasic*)data;
					const Process& p = _pc->GetProcessFromDtb(s->GetDtb());
					RemoveSSH(p.GetPid());
				}
				catch(...)
				{
					cerr << "could not find process KILL" <<  endl;
				}

				_sm->Unlock();
			}
			return false;
		}
};
KillListener* killListener;

class SendToListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				vmi_instance_t vmi = _sm->Lock();

				SyscallBasic* s = (SyscallBasic*)data;
				// uint64_t fd = s->GetParameter(0);

				const Process& p = _pc->GetProcessFromDtb(s->GetDtb());
				vmi_pid_t parent = _pc->FindParentProcessPidByPid(p.GetPid(), _sshd_parent_pid);
				vector<sshchild>::iterator it2 = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if(it2 != sshchildren.end())
				{
					// cout << dec << fd << " - " << p.GetName() << " - " << p.GetPid() << endl;
					// get(to_string(parent)+"net")->info("Port forward payload :\n{0}", hexdumptostring(cd, payloadSize));
					uint64_t addr = s->GetParameter(4);
					if(addr != 0)
					{
						sockaddr_in* _sockaddr_in = new sockaddr_in();

						vmi_read_va(vmi, addr, p.GetPid(), sizeof(sockaddr_in), _sockaddr_in, NULL);
						// cout << inet_ntoa(_sockaddr_in->sin_addr) << endl;
						// cout << dec << _sockaddr_in->sin_port << endl;

						get(std::to_string((*it2).pid)+"net")->info("New Connection (SENDTO) - To : [{0:s}] Proc Name : [{1}] Pid : [{2:d}] Size : [{3:d}]", inet_ntoa(_sockaddr_in->sin_addr), p.GetName(), p.GetPid(), s->GetParameter(2));
						get(std::to_string((*it2).pid)+"net")->flush();

						delete _sockaddr_in;

						// cout << hex << addr << endl;
						// sockaddr* test = (struct sockaddr*)&addr;
						// sockaddr_in* test2 = (struct sockaddr_in*)test;
						// cout << inet_ntoa(test2->sin_addr) << endl;
						// (struct in_addr*)&saddr
					}
				}

				_sm->Unlock();
			}
			return false;
		}
};
SendToListener* sendToListener;

class WriteListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				vmi_instance_t vmi = _sm->Lock();

				SyscallBasic* s = (SyscallBasic*)data;
				uint64_t fd = s->GetParameter(0);
				size_t fileSize = s->GetParameter(2);

				const Process& p = _pc->GetProcessFromDtb(s->GetDtb());

				char* cd = new char[fileSize];

				_sshhelper->GetChar(vmi, s->GetDtb(), s->GetParameter(1), cd, fileSize);

				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == p.GetPid());
				if (it != sshchildren.end())
				{
					if(fd == 6)
					{
						if(fileSize < 300)
						{
							get(to_string((*it).pid)+"write")->info("Keystroke (write)\n{0}",hexdumptostring(cd, fileSize));
						}
					}
				}
				else
				{
					vmi_pid_t parent = _pc->FindParentProcessPidByPid(p.GetPid(), _sshd_parent_pid);
					vector<sshchild>::iterator it2 = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
					if(it2 != sshchildren.end())
					{
						vector<writefile>::iterator it33 = find_if(writefiles.begin(), writefiles.end(), writefind(p.GetPid(), parent, fd));
						if(it33 == writefiles.end())
						{
							vector<OpenFile> af = _linux->GetOpenFiles(p);
							for (vector<OpenFile>::iterator ita = af.begin() ; ita != af.end(); ++ita)
							{
								if((*ita).write)
								{
									if(fd < 3) continue;

									if((*ita).path != "/dev/null")
									{
										writefile wf;
										wf.pid = p.GetPid();
										wf.parent = parent;
										wf.fd = fd;
										wf.path = (*ita).path;
										wf.offset = 0;
										wf.fseek = false;
										find_and_replace(wf.path,"/","_");
										string name = p.GetName();
										wf.name = name;
										writefiles.push_back(wf);
									}
								}
							}
						}

						vector<writefile>::iterator it3 = find_if(writefiles.begin(), writefiles.end(), writefind(p.GetPid(), parent, fd));
						if (it3 != writefiles.end())
						{
							//seek -> appending something
							if((*it3).fseek)
							{
								//create new file incase like nano
								ofstream binFile1(_log_dir+to_string((*it2).pid)+"_"+to_string((*it3).pid)+"_"+(*it3).name+"_"+to_string((*it3).fd)+"---"+(*it3).path, ios::out | ios::binary | ios_base::app);
								if (binFile1.is_open())
								{
									binFile1.write("",0);
								}

								ofstream binFile(_log_dir+to_string((*it2).pid)+"_"+to_string((*it3).pid)+"_"+(*it3).name+"_"+to_string((*it3).fd)+"---"+(*it3).path, ios_base::in | ios_base::out | ios_base::ate);
								if (binFile.is_open())
								{
									binFile.seekp((*it3).offset);
									binFile.write(cd, fileSize);
								}
							}
							else //if((*it3).offset == 0)
							{
								ofstream binFile2(_log_dir+to_string((*it2).pid)+"_"+to_string((*it3).pid)+"_"+(*it3).name+"_"+to_string((*it3).fd)+"---"+(*it3).path, ios::out | ios::binary | ios_base::app);
								if (binFile2.is_open())
								{
									binFile2.write(cd, fileSize);
									(*it3).offset = (*it3).offset + fileSize;
								}
							}
							get(to_string((*it2).pid)+"write")->info("Write\nproc name:{0}\npath : {0}\n{0}",(*it3).name,(*it3).path);
						}
					}
				}

				delete[] cd;

				_sm->Unlock();
			}
			return false;
		}
};
WriteListener* writeListener;

class CloseListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				SyscallBasic* s = (SyscallBasic*)data;

				const Process& p = _pc->GetProcessFromDtb(s->GetDtb());
				vmi_pid_t pid = p.GetPid();

				for(vector<writefile>::iterator it3 = writefiles.begin(); it3 != writefiles.end();)
				{
					if((*it3).pid == pid && (*it3).fd == s->GetParameter(0))
					{
						(*it3).name.clear();
						(*it3).name.shrink_to_fit();
						(*it3).path.clear();
						(*it3).path.shrink_to_fit();
						it3 = writefiles.erase(it3);
					}
					else
					{
						++it3;
					}
				}
			}
			return false;
		}
};
CloseListener* closeListener;

class LSeekListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			SyscallEvent* sev = dynamic_cast<SyscallEvent*>(ev);
			if(sev)
			{
				vmi_instance_t vmi = _sm->Lock();

				SyscallBasic* s = (SyscallBasic*)data;

				const Process& p = _pc->GetProcessFromDtb(s->GetDtb());

				vector<writefile>::iterator it3 = find_if(writefiles.begin(), writefiles.end(), (boost::bind(&writefile::pid, _1) == p.GetPid(),boost::bind(&writefile::fd, _1) == s->GetParameter(0)));
				if (it3 != writefiles.end())
				{
					(*it3).fseek = true;
					(*it3).offset = s->GetParameter(1);
				}
				else
				{
					vmi_pid_t parent = _pc->FindParentProcessPidByPid(s->GetPid(vmi), _sshd_parent_pid);
					vector<writefile>::iterator it33 = find_if(writefiles.begin(), writefiles.end(), writefind(p.GetPid(),parent,s->GetParameter(0)));
					if(it33 == writefiles.end())
					{
						vector<OpenFile> af = _linux->GetOpenFiles(p);
						for (vector<OpenFile>::iterator ita = af.begin() ; ita != af.end(); ++ita)
						{
							if((*ita).write)
							{
								if(s->GetParameter(0) < 3) continue;

								if((*ita).path != "/dev/null")
								{
									writefile wf;
									wf.pid = p.GetPid();
									wf.parent = parent;
									wf.fd = s->GetParameter(0);
									wf.path = (*ita).path;
									wf.offset = s->GetParameter(1);
									wf.fseek = false;
									find_and_replace(wf.path,"/","_");
									string name = p.GetName();
									wf.name = name;
									writefiles.push_back(wf);
								}
							}
						}
					}
				}

				_sm->Unlock();
			}
			return false;
		}
};
LSeekListener* lseekListener;

class BuffGetU8Listener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			ProcessBreakpointEvent* sev = dynamic_cast<ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				vmi_instance_t vmi = _sm->Lock();

				addr_t dtb = a->regs.cr3;
				const Process& p = _pc->GetProcessFromDtb(dtb);
				vmi_pid_t pid = p.GetPid();

				uint64_t p1 = a->regs.rdi;

				vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);
				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					bool ok = false;
					size_t off = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->off_in_sshbuf_offset);
					addr_t cd_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->cd_in_sshbuf_offset);
					if(cd_addr != 0)
					{
						ok = true;
					}

					if(ok)
					{
						uint64_t typep = _sshhelper->GetOneByteNumber(vmi, dtb, cd_addr+off);

						// 94 -> stdin
						// 98 -> exec inline ssh
						if(typep == 94 || typep == 98)
						{
							size_t size = _sshhelper->GetSizeT(vmi, dtb, p1+_sshhelper->size_in_sshbuf_offset);
							size_t real_size = size - off;

							size_t max_size = _sshhelper->GetSizeT(vmi, dtb, p1+_sshhelper->max_size_in_sshbuf_offset);

							if(real_size < max_size)
							{
								int payloadOffset = 9;
								int payloadSize = real_size-9;

								char* cd = new char[payloadSize];

								_sshhelper->GetChar(vmi, dtb, cd_addr+off+payloadOffset, cd, payloadSize);

								//cout << hexdumptostring(cd, payloadSize) << endl;
								get(to_string(parent))->info("Receive Packet : [{0:d}] size [{1:d}]\n{2}", typep, payloadSize, hexdumptostring(cd, payloadSize));

								delete[] cd;
							}
						}
					}
				}
				else
				{
					// get(to_string(parent))->info("Receive Packet : [{0:d}]\n", typep);
				}
				_sm->Unlock();
			}

			return false;
		}
};
BuffGetU8Listener* buffGetU8Listener;

class PacketSend2WrappedListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			ProcessBreakpointEvent* sev = dynamic_cast<ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				vmi_instance_t vmi = _sm->Lock();

				addr_t dtb = a->regs.cr3;
				uint64_t p1 = a->regs.rdi;

				const Process& p = _pc->GetProcessFromDtb(dtb);
				vmi_pid_t pid = p.GetPid();
				vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);

				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					// vmi_v2pcache_flush(vmi, ~0ull);
					// vmi_pidcache_flush(vmi);

					bool ok = false;

					addr_t cd_addr = 0;
					addr_t outGoingPacketAddr = 0;
					uint64_t typep = 0;
					size_t off = 0;

					addr_t state_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->session_state_in_ssh_offset);
					if(state_addr != 0)
					{
						// addr_t sshcipher = _sshhelper->GetAddrT(vmi, dtb, state_addr+_sshhelper->send_context_in_session_state_offset+_sshhelper->sshcipher_in_sshcipher_ctx_offset);
						// if(sshcipher != 0)
						// {
						// 	addr_t name_addr_va = _sshhelper->GetAddrT(vmi, dtb, sshcipher);
						// 	addr_t name_addr_pa = _sshhelper->TranslateVaToPa(vmi, dtb, name_addr_va);
						// 	if(name_addr_pa != 0)
						// 	{
						// 		char* name;
						// 		name = vmi_read_str_pa(vmi, name_addr_pa);
						// 		string name_str = string(name);
						// 		// (*it).username = user;
						// 		cout << name_str << endl;
						// 		free(name);

						// 		u_int block_size = _sshhelper->GetOneByteNumber(vmi, dtb, sshcipher+_sshhelper->block_size_in_sshcipher);
						// 		u_int key_len = _sshhelper->GetOneByteNumber(vmi, dtb, sshcipher+_sshhelper->key_len_in_sshcipher);
						// 		u_int iv_len = _sshhelper->GetOneByteNumber(vmi, dtb, sshcipher+_sshhelper->iv_len_in_sshcipher);

						// 		cout << "block size : " << dec << block_size << endl;
						// 		cout << "key len : " << dec << key_len << endl;
						// 		cout << "iv len : " << dec << iv_len << endl;
						// 	}
						// }
						// else
						// {
						// 	cout << "aa" << endl;
						// }

						outGoingPacketAddr = _sshhelper->GetAddrT(vmi, dtb, state_addr+_sshhelper->outgoing_packet_in_session_state_offset);
						if(outGoingPacketAddr != 0)
						{
							off = _sshhelper->GetSizeT(vmi, dtb, outGoingPacketAddr+_sshhelper->off_in_sshbuf_offset);
							cd_addr = _sshhelper->GetAddrT(vmi, dtb, outGoingPacketAddr+_sshhelper->cd_in_sshbuf_offset);
							if(cd_addr != 0)
							{
								typep = _sshhelper->GetOneByteNumber(vmi, dtb, cd_addr + 5);
								ok = true;
							}
						}
					}

					if(ok)
					{
						//bash only then -> 0, if port forward, bash -> 2 , forward payload -> 3
						uint64_t packetType = _sshhelper->GetOneByteNumber(vmi, dtb, cd_addr + 9);

						if(typep == 94 || typep == 98)
						{
							size_t size = _sshhelper->GetSizeT(vmi, dtb, outGoingPacketAddr+_sshhelper->size_in_sshbuf_offset);
							size_t real_size = size - off;

							size_t max_size = _sshhelper->GetSizeT(vmi, dtb, outGoingPacketAddr+_sshhelper->max_size_in_sshbuf_offset);

							if(real_size < max_size)
							{
								// char* temp = new char[50];
								// vmi_read_va(vmi,cd_addr, pid, 50, temp, NULL);
								// cout << hexdumptostring(temp, 50) << endl;
								// delete[] temp;

								int payloadOffset = 5+9;
								int payloadSize = real_size-9-5;

								char* cd = new char[payloadSize];

								_sshhelper->GetChar(vmi, dtb, cd_addr+payloadOffset, cd, payloadSize);

								get(to_string(parent))->debug("Send Packet : [{0:d}] size [{1:d}]\n", typep, payloadSize);

								if(typep == 94)
								{
									string escaped = escape_json(string(cd, payloadSize));
									time_t currentTime = chrono::system_clock::now().time_since_epoch() / chrono::milliseconds(1);
									vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);

									if(packetType == 0 || packetType == 2)
									{
										if((*it).lastPacketSend == 0)
										{
											get(to_string(parent)+"json")->info("[0.1,\"{0}\"]", escaped);    
											get(to_string(parent)+"json")->flush();
										}
										else
										{
											float timeDistance = (float)(currentTime - (*it).lastPacketSend)/(float)1000;
							
											get(to_string(parent)+"json")->info(",[{0},\"{1}\"]", timeDistance, escaped);
											get(to_string(parent)+"json")->flush();
										}
									}
									else if((*it).portForward && packetType == 3)
									{
										get(to_string(parent)+"net")->info("Port forward payload :\n{0}", hexdumptostring(cd, payloadSize));
										get(to_string(parent)+"net")->flush();
									}
									
									(*it).lastPacketSend = currentTime;
								}
								delete[] cd;
							}
						}
					}
				}
				_sm->Unlock();	
			}

			return false;
		}
};
PacketSend2WrappedListener* packetSend2WrappedListener;

class AuthPasswordPostListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			ProcessBreakpointEvent* sev = dynamic_cast<ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(!a->beforeSingleStep)
					return false;

				vmi_instance_t vmi = _sm->Lock();

				uint32_t vcpu = a->vcpu;
				uint64_t rax = 3;

				vmi_get_vcpureg(vmi, &rax, RAX, vcpu);

				if(rax == 1 || rax == 0)
				{
					if(vmi_set_vcpureg(vmi, 1, RAX, vcpu) == VMI_FAILURE)
					{
						cout << "failed to change RAX" << endl;
					}
				}

				_sm->Unlock();
			}

			return false;
		}
};
AuthPasswordPostListener* authPasswordPostListener;

addr_t _post_auth_pa = 0;
ProcessBreakpointEvent* _authPasswordPostEvent;

class AuthPasswordListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			ProcessBreakpointEvent* sev = dynamic_cast<ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				vmi_instance_t vmi = _sm->Lock();

				addr_t dtb = a->regs.cr3;
				uint64_t p1 = a->regs.rdi;
				uint64_t p2 = a->regs.rsi;

				const Process& p = _pc->GetProcessFromDtb(dtb);
				vmi_pid_t pid = p.GetPid();
				vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);

				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					uint64_t valid = _sshhelper->GetOneByteNumber(vmi, dtb, p1+_sshhelper->valid_in_authctxt_offset);

					if(_modify_auth == 1)
					{
						if(valid == 1)
						{
							addr_t stack_addr_pa = _sshhelper->TranslateVaToPa(vmi, dtb, a->regs.rsp);
							if(stack_addr_pa != 0)
							{
								addr_t return_addr_va = 0;
								vmi_read_64_pa(vmi, stack_addr_pa, &return_addr_va);

								addr_t return_addr_pa = _sshhelper->TranslateVaToPa(vmi, dtb, return_addr_va);

								if(return_addr_pa != 0)
								{
									if(_post_auth_pa == 0)
									{
										//first time, init.
										_post_auth_pa = return_addr_pa;
										_authPasswordPostEvent = new ProcessBreakpointEvent("authPasswordPostEvent", 0, return_addr_pa, *authPasswordPostListener);
										_sm->GetBPM()->InsertBreakpoint(_authPasswordPostEvent);
									}
									else if(_post_auth_pa != return_addr_pa)
									{
										//somehow the return add change
										_post_auth_pa = return_addr_pa;

										//delete the old one
										_sm->GetBPM()->RemoveBreakpoint(_authPasswordPostEvent);
										delete _authPasswordPostEvent;

										//create the new one
										_authPasswordPostEvent = new ProcessBreakpointEvent("authPasswordPostEvent", 0, return_addr_pa, *authPasswordPostListener);
										_sm->GetBPM()->InsertBreakpoint(_authPasswordPostEvent);
									}
								}
							}
						}
					}

					uint64_t failures = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->failures_in_authctxt_offset);

					addr_t username_va = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->user_in_authctxt_offset);
					string user = "";
					(*it).username = "";

					if(username_va != 0)
					{
						addr_t username_pa = _sshhelper->TranslateVaToPa(vmi, dtb, username_va);
						if(username_pa != 0)
						{
							char* username;
							username = vmi_read_str_pa(vmi, username_pa);
							user = string(username);
							(*it).username = user;
							free(username);
						}
					}

					string pass = "";

					addr_t password_pa = _sshhelper->TranslateVaToPa(vmi, dtb, p2);
					if(password_pa != 0)
					{
						char* password;
						password = vmi_read_str_pa(vmi, password_pa);
						pass = string(password);
						free(password);
					}
					
					get(to_string(parent))->info("Username : [{0}] Password : [{1}]\nValid user : [{2:d}] failure : [{3:d}]", user, pass, valid, failures);
					get(to_string(parent))->flush();
				}

				_sm->Unlock();	
			}

			return false;
		}
};
AuthPasswordListener* authPasswordListener;

class ChannelConnectToPortListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			ProcessBreakpointEvent* sev = dynamic_cast<ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				vmi_instance_t vmi = _sm->Lock();

				addr_t dtb = a->regs.cr3;
				uint64_t p1 = a->regs.rdi;
				uint64_t p2 = a->regs.rsi;

				const Process& p = _pc->GetProcessFromDtb(dtb);
				vmi_pid_t pid = p.GetPid();
				vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);

				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					addr_t target_pa = _sshhelper->TranslateVaToPa(vmi, dtb, p1);
					if(target_pa != 0)
					{
						char* target = vmi_read_str_pa(vmi, target_pa);
						get(to_string(parent)+"net")->info("Port Forward - Target IP : [{0}] Port : [{1:d}]\n", target, p2);
						get(to_string(parent)+"net")->flush();
						(*it).portForward = true;

						free(target);
					}
				}

				_sm->Unlock();	
			}

			return false;
		}
};
ChannelConnectToPortListener* channelConnectToPortListener;

class KexDerivedBeginListener : public EventListener
{
	public:
		bool callback(Event* ev, void* data)
		{
			ProcessBreakpointEvent* sev = dynamic_cast<ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				vmi_instance_t vmi = _sm->Lock();

				addr_t dtb = a->regs.cr3;
				uint64_t p1 = a->regs.rdi;

				const Process& p = _pc->GetProcessFromDtb(dtb);
				vmi_pid_t pid = p.GetPid();
				vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);

				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					(*it).sshAddr = p1;

					string ip = "";

					addr_t remote_ip_addr_va = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->remote_ipaddr_in_ssh_offset);
					if(remote_ip_addr_va != 0)
					{
						addr_t remote_ip_addr_pa = _sshhelper->TranslateVaToPa(vmi, dtb, remote_ip_addr_va);
						char* remote_ip = vmi_read_str_pa(vmi, remote_ip_addr_pa);
						ip = string(remote_ip);
						free(remote_ip);
					}

					uint64_t remote_port = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->remote_port_in_ssh_offset);

					get(to_string(parent))->warn("Remote IP : {0}", ip);
					get(to_string(parent))->warn("Remote Port : {0:d}", remote_port);
				}

				_sm->Unlock();	
			}

			return false;
		}
};
KexDerivedBeginListener* kexDerivedBeginListener;

class SaraceniaConnectionFilter : public PacketFilter
{
	public:
		bool filter(Packet* p)
		{
			try
			{
				if(p->is_tcp())
				{
					return true;
				}

				if(p->is_syn())
				{
					return true;
				}
			}
			catch(...)
			{

			}
			return false;
		}

		void callback(Packet* p)
		{
			_sm->Lock();

			NetworkConnection t = NetworkConnection(0, 0, p->get_ipv4_src(), p->get_ipv4_dst(), p->get_sport(), p->get_dport());
			try
			{
				const Process& process = _pc->GetProcessFromTCPConnection(&t);
				vmi_pid_t parent = _pc->FindParentProcessPidByPid(process.GetPid(), _sshd_parent_pid);
				vector<sshchild>::iterator it = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == parent);
				if (it != sshchildren.end())
				{
					if(process.GetPid() != (*it).pid)
					{
						get(std::to_string((*it).pid)+"net")->info("New Connection - From : [{0}:{1:d}] To : [{2}:{3:d}] Proc Name : [{4}] Pid : [{5:d}] Size : [{6:d}]",(string)p->get_ipv4_src(),p->get_sport(),(string)p->get_ipv4_dst(), p->get_dport(), process.GetName(), process.GetPid(), p->getSize());
						get(std::to_string((*it).pid)+"net")->flush();
					}
				}
			}
			catch(...)
			{

			}

			_sm->Unlock();
		}
};

int main(int argc, char* argv[]) 
{
	if (argc != 3)
	{
		cout << argv[0] << " <vmname> <setting json>" << endl;
		return -1;
	}

	cout << "  _____         _____                    " << endl;
	cout << " / ____|  /\\   |  __ \\    /\\             " << endl;
	cout << "| (___   /  \\  | |__) |  /  \\            " << endl;
	cout << " \\___ \\ / /\\ \\ |  _  /  / /\\ \\           " << endl;
	cout << " ____) / ____ \\| | \\ \\ / ____ \\          " << endl;
	cout << "|_____/_____ ______ __/__ _____\\         " << endl;
	cout << "      / ____|  ____| \\ | |_   _|   /\\    " << endl;
	cout << "     | |    | |__  |  \\| | | |    /  \\   " << endl;
	cout << "     | |    |  __| | . ` | | |   / /\\ \\  " << endl;
	cout << "     | |____| |____| |\\  |_| |_ / ____ \\ " << endl;
	cout << "      \\_____|______|_| \\_|_____/_/    \\_\\" << endl;
	cout << endl;

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	//sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	auto console = stdout_color_mt<spdlog::async_factory>("console");
	get("console")->info("Reading setting file");

	Setting setting(argv[2]);
	_log_dir = setting.GetStringValue("log_dir");
	_sshd_bin_path = setting.GetStringValue("sshd_bin_path");
	_sshd_path = setting.GetStringValue("sshd_path");
	_profile = setting.GetStringValue("profile");
	_bp_type = setting.GetIntValue("bp_type");
	_modify_auth = setting.GetIntValue("modify_auth");
	_process_change = setting.GetIntValue("process_change_mode");
	_ip = setting.GetStringValue("ip");

	if(_process_change == 1)
	{
		_processes_list = setting.GetArrayString("white_list");
	}
	else if(_process_change == 2)
	{
		_processes_list = setting.GetArrayString("black_list");
	}

	auto parent_logger = basic_logger_mt("parent",_log_dir+"parent.txt");

	parent_logger->set_pattern("[%H:%M:%S][%n] %v");

	get("console")->info("Setting up system monitor");

	_sm = std::make_shared<SystemMonitor>(argv[1], true, _bp_type > 1);
	_linux = std::make_shared<LinuxVM>(_sm);

	ProcessCache pc(*_linux);
	_pc = &pc;

	get("console")->info("Reading the debug symbol");

	SSHHelper sshhelper(_sshd_bin_path, _ip);
	sshhelper.GetOffsets();
	//sshhelper.OpenSSHConnection();
	_sshhelper = &sshhelper;

	NetMonitor nm("eth0", "");
	_nm = &nm;
	nm.Init();

	SaraceniaConnectionFilter scf;
	
	if(FindSSHDParent())
	{
		get("parent")->info("Parent PID : {0:d}", _sshd_parent_pid);
		get("console")->info("Parent PID : {0:d}", _sshd_parent_pid);
		get("console")->info("[auth_password] VA : {0:x} PA : {1:x}", sshhelper.auth_password_va, sshhelper.auth_password_pa);
		get("console")->info("[kex_derive_keys] VA : {0:x} PA : {1:x}", sshhelper.kex_derive_keys_va, sshhelper.kex_derive_keys_pa);
		get("console")->info("[do_authentication2] VA : {0:x} PA : {1:x}", sshhelper.do_authentiation2_va, sshhelper.do_authentiation2_pa);
		get("console")->info("[sshbuf_get_u8] VA : {0:x} PA : {1:x}", sshhelper.sshbuf_get_u8_va, sshhelper.sshbuf_get_u8_pa);
		get("console")->info("[ssh_packet_send2_wrapped] VA : {0:x} PA : {1:x}", sshhelper.ssh_packet_send2_wrapped_va, sshhelper.ssh_packet_send2_wrapped_pa);
		get("console")->info("[channel_connect_to_port] VA : {0:x} PA : {1:x}", sshhelper.channel_connect_to_port_va, sshhelper.channel_connect_to_port_pa);
		
		vmi_instance_t vmi = _sm->Lock();
		addr_t xen_interrupt_va = 0;
		addr_t xen_interrupt_pa = 0;
		vmi_translate_ksym2v(vmi, (char*)"xen_hvm_callback_vector", &xen_interrupt_va);
		vmi_translate_kv2p(vmi, xen_interrupt_va, &xen_interrupt_pa);
		_sm->AddExludeAddress(xen_interrupt_pa);
		_sm->Unlock();

		get("console")->info("[xen_hvm_callback_vector] VA : {0:x} PA : {1:x}", xen_interrupt_va, xen_interrupt_pa);
	
		buffGetU8Listener = new BuffGetU8Listener();
		ProcessBreakpointEvent* buffGetU8Event = new ProcessBreakpointEvent("SSHBuffGetU8Listener", 0, sshhelper.sshbuf_get_u8_pa, *buffGetU8Listener);
		_sm->GetBPM()->InsertBreakpoint(buffGetU8Event);
		// UNUSED(buffGetU8Event);
		
		packetSend2WrappedListener = new PacketSend2WrappedListener();
		ProcessBreakpointEvent* packetSend2WrappedEvent = new ProcessBreakpointEvent("PacketSend2WrappedListener", 0, sshhelper.ssh_packet_send2_wrapped_pa, *packetSend2WrappedListener);
		_sm->GetBPM()->InsertBreakpoint(packetSend2WrappedEvent);
		// UNUSED(packetSend2WrappedEvent);

		// char* testing = new char[8];
		// vmi_read_pa(vmi, sshhelper.auth_password_pa, 8, testing, NULL);
		// cout << hexdumptostring(testing, 8) << endl;
		// delete[] testing;
		
		authPasswordListener = new AuthPasswordListener();
		ProcessBreakpointEvent* authPasswordEvent = new ProcessBreakpointEvent("AuthPasswordListener", 0, sshhelper.auth_password_pa, *authPasswordListener);
		_sm->GetBPM()->InsertBreakpoint(authPasswordEvent);

		// vmi_read_pa(vmi, sshhelper.auth_password_pa, 8, testing, NULL);
		// cout << hexdumptostring(testing, 8) << endl;
		// delete[] testing;
		// UNUSED(authPasswordEvent);
		authPasswordPostListener = new AuthPasswordPostListener();

		kexDerivedBeginListener = new KexDerivedBeginListener();
		ProcessBreakpointEvent* kexDerivedBeginEvent = new ProcessBreakpointEvent("KexDerivedBeginListener", 0, sshhelper.kex_derive_keys_pa, *kexDerivedBeginListener);
		_sm->GetBPM()->InsertBreakpoint(kexDerivedBeginEvent);
		// UNUSED(kexDerivedBeginEvent);
		// kexDerivedBeginPostListener = new KexDerivedBeginPostListener();

		channelConnectToPortListener = new ChannelConnectToPortListener();
		ProcessBreakpointEvent* channelConnectToPortEvent = new ProcessBreakpointEvent("ChannelConnectToPortListener", 0, sshhelper.channel_connect_to_port_pa, *channelConnectToPortListener);
		_sm->GetBPM()->InsertBreakpoint(channelConnectToPortEvent);
		// UNUSED(channelConnectToPortEvent);

		cloneListener = new CloneListener();
		cloneS = new SyscallEvent(56, *cloneListener, true, false, false);
		killListener = new KillListener();
		killS = new SyscallEvent(231, *killListener, false, false, false);
		writeListener = new WriteListener();
		writeS = new SyscallEvent(1, *writeListener, false, false, false);
		closeListener = new CloseListener();
		closeS = new SyscallEvent(3, *closeListener, false, false, true);
		lseekListener = new LSeekListener();
		lseekS = new SyscallEvent(8, *lseekListener, false, false, false);
		execListener = new ExecListener();
		execveS = new SyscallEvent(59, *execListener, false, false, true);
		sendToListener = new SendToListener();
		sendToS = new SyscallEvent(44, *sendToListener, false, false, false);

		_linux->RegisterSyscall(*cloneS);
		_linux->RegisterSyscall(*killS);
		_linux->RegisterSyscall(*writeS);
		_linux->RegisterSyscall(*closeS);
		_linux->RegisterSyscall(*execveS);
		_linux->RegisterSyscall(*sendToS);

		if(_process_change != 0)
		{
			processChangeListener = new ProcessChangeListener();
			process_change = new ProcessChangeEvent(*processChangeListener);

			_linux->RegisterProcessChange(*process_change);
		}
		
		get("console")->info("Saracenia is ready");

		_nm->RegisterFilter(&scf);
		_nm->Loop();
	}
	else
	{
		get("console")->error("SSHD parent not found");
		interrupted = true;
	}

	while(!interrupted) 
	{
		sleep(1);
	}

	return 0;
}

bool FindSSHDParent()
{
	vector<Process> processes = _linux->GetProcessList();
	for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
	{
		if((*it).GetName() == "sshd" && (*it).GetParentPid() == 1)
		{
			_sshd_parent_pid = (*it).GetPid();
			_sshhelper->GetAddresses(_linux.get(), (*it));

			return true;
		}
	}

	return false;
}

void FindNewSSHD(vmi_pid_t pid)
{
	vector<Process> processes = _linux->GetProcessList();
	for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
	{
		if((*it).GetName() == "sshd" && (*it).GetPid() == pid)
		{
			bool exist(false);
			vector<sshchild>::iterator it2 = find_if(sshchildren.begin(), sshchildren.end(), boost::bind(&sshchild::pid, _1) == (*it).GetPid());
			if (it2 != sshchildren.end())
			{
				exist = true;
				break;
			}

			if(!exist)
			{
				auto child_main_logger = basic_logger_mt<async_factory>(to_string((*it).GetPid()), _log_dir+to_string((*it).GetPid())+".ssh");
				auto child_json_logger = basic_logger_mt<async_factory>(to_string((*it).GetPid())+"json", _log_dir+to_string((*it).GetPid())+".json");
				auto child_net_logger = basic_logger_mt<async_factory>(to_string((*it).GetPid())+"net", _log_dir+to_string((*it).GetPid())+".net");
				auto child_open_logger = basic_logger_mt<async_factory>(to_string((*it).GetPid())+"open", _log_dir+to_string((*it).GetPid())+".open");
				auto child_exec_logger = basic_logger_mt<async_factory>(to_string((*it).GetPid())+"exec", _log_dir+to_string((*it).GetPid())+".exec");
				auto child_write_logger = basic_logger_mt<async_factory>(to_string((*it).GetPid())+"write", _log_dir+to_string((*it).GetPid())+".write");

				child_main_logger->set_pattern("[%c][%n] %v");
				child_json_logger->set_pattern("%v");
				child_net_logger->set_pattern("[%c][%n] %v");
				child_open_logger->set_pattern("[%c][%n] %v");
				child_exec_logger->set_pattern("[%c][%n] %v");
				child_write_logger->set_pattern("[%c][%n] %v");

				child_json_logger->info("{\"version\": 1,\"width\": 80,\"height\": 24,\"duration\": 1.515658,\"command\": \"/bin/zsh\",\"title\": \"\",\"env\": {\"TERM\": \"xterm-256color\",\"SHELL\": \"/bin/zsh\"},\"stdout\": [");
				child_json_logger->flush();
				get("parent")->info("New SSH PID : {0:d}",(*it).GetPid());
				get("parent")->flush();

				sshchild a;
				a.pid = (*it).GetPid();
				a.lastPacketSend = 0;
				a.sshAddr = 0;
				a.sub_pid = 0;
				a.username = "root";
				a.tmp = 0;
				a.authPass = 0;
				a.portForward = false;
				
				// cout << "new ssh " << dec << a.pid << endl;

				sshchildren.push_back(a);
			}
		}
	}
}

void RemoveSSH(vmi_pid_t pid)
{
	for(vector<sshchild>::iterator it = sshchildren.begin() ; it!=sshchildren.end() ; )
	{
		if((*it).pid == pid)
		{
			get("parent")->info("Deregister and delete child PID : {0:d}",(*it).pid);
			get(to_string((*it).pid)+"json")->info("]}");

			get(to_string((*it).pid))->flush();
			get(to_string((*it).pid)+"json")->flush();
			get(to_string((*it).pid)+"net")->flush();
			get(to_string((*it).pid)+"exec")->flush();
			get(to_string((*it).pid)+"open")->flush();
			get(to_string((*it).pid)+"write")->flush();

			drop(to_string((*it).pid));
			drop(to_string((*it).pid)+"json");
			drop(to_string((*it).pid)+"net");
			drop(to_string((*it).pid)+"exec");
			drop(to_string((*it).pid)+"open");
			drop(to_string((*it).pid)+"write");

			(*it).username.clear();
			(*it).username.shrink_to_fit();
			it = sshchildren.erase(it);
		}
		else
		{
			++it;
		}
	}
}
