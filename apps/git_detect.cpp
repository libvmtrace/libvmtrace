
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

#include <iostream>
#include <vector>
#include <boost/bind.hpp>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <string>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include <ssh_helper/SSHHelper.hpp>

using namespace std;
using namespace libvmtrace;
using namespace libvmtrace::util;
using namespace helpers;
using namespace spdlog;

LinuxVM* _linux;
SystemMonitor* _sm;
SSHHelper* _sshhelper;
ProcessCache* _pc;
// elastic* _e;
ElasticLogger* _el;

string _sshd_bin_path = "";
string _sshd_path = "";
string _ip = "";
vmi_pid_t _sshd_parent_pid = 0;
int _bp_type = 0;
string _es_path = "";

// sqlite3 *db;

bool FindSSHDParent();

struct sshchild_git
{
	vmi_pid_t parent_sshd;
	vmi_pid_t child_sshd;
	bool git;
	string ip;
	string repo;
	bool upload;
	vector<string> data;
	vector<string> inconsistent;
};

vector<sshchild_git> sshchild_git_children;

static bool interrupted = false;
static void close_handler(int sig)
{
	if (sig == SIGSEGV) 
	{
		_sm->GetBPM()->DeInit();
		_sm->Stop();
	}

	interrupted = true;
}

// int callback(void *NotUsed, int argc, char **argv, char **szColName)
// {
// 	for(int i = 0 ; i < argc ; i++)
// 	{
// 		cout << szColName[i] << " = " << argv[i] << endl;
// 	}

// 	return 0;
// }

// bool ExecuteQuery(string query)
// {
// 	char *msg = 0;
// 	int rc = sqlite3_exec(db, query.c_str(), callback, 0, &msg);
// 	if(rc != SQLITE_OK)
// 	{
// 		cout << msg << endl;
// 		return false;
// 	}

// 	return true;
// }

class CloneListener : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			const SyscallEvent* sev = dynamic_cast<const SyscallEvent*>(ev);
			if(sev)
			{
				// cout << "called" << endl;
				vmi_instance_t vmi = _sm->Lock();
				UNUSED(vmi);

				SyscallBasic* s = (SyscallBasic*)data;
				addr_t dtb = s->GetDtb();

				//vmi_v2pcache_flush(vmi, ~0ull);
				try
				{
					_pc->UpdateList();
					const Process& p = _pc->GetProcessFromDtb(dtb);
					const vmi_pid_t pid = p.GetPid();
					const vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);
					UNUSED(parent);

					//get("console")->info("Clone : {0:d} : {1:d} - {2:d}", pid, parent, s->GetRet());
					//get("console")->flush();
					// cout << dec << pid << " - " << s->GetRet() << endl;
					if(pid == _sshd_parent_pid)
					{
						vector<sshchild_git>::iterator it = find_if(sshchild_git_children.begin(), sshchild_git_children.end(), boost::bind(&sshchild_git::parent_sshd, _1) == pid);
						if(it == sshchild_git_children.end())
						{
							sshchild_git a;
							a.parent_sshd = s->GetRet();
							a.child_sshd = 0;
							a.git = false;
							a.ip = "";
							a.repo = "";
							a.upload = false;
							// a.inconsistent = false;

							sshchild_git_children.push_back(a);
						}
					}
					else if(p.GetParentPid() == _sshd_parent_pid)
					{
						if(s->GetRet() > (uint64_t)(pid + 1))
						{
							vector<sshchild_git>::iterator it = find_if(sshchild_git_children.begin(), sshchild_git_children.end(), boost::bind(&sshchild_git::parent_sshd, _1) == pid);
							if(it != sshchild_git_children.end())
							{
								(*it).child_sshd = s->GetRet();
							}
						}
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

// static int counting = 0;
class BuffGetU8Listener : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			const ProcessBreakpointEvent* sev = dynamic_cast<const ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				// counting++;
				// vmi_v2pcache_flush(vmi, ~0ull);

				addr_t dtb = a->regs.cr3;
				const Process& p = _pc->GetProcessFromDtb(dtb);
				if(p.GetPid() == _sshd_parent_pid)
				{
					return false;
				}

				vector<sshchild_git>::iterator it = find_if(sshchild_git_children.begin(), sshchild_git_children.end(), boost::bind(&sshchild_git::child_sshd, _1) == p.GetPid());
				if(it == sshchild_git_children.end())
				{
					// return false;

					vmi_instance_t vmi = _sm->Lock();
					vmi_v2pcache_flush(vmi, ~0ull);
					uint64_t p1 = a->regs.rdi;
					size_t off = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->off_in_sshbuf_offset);
					addr_t cd_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->cd_in_sshbuf_offset);
					if(cd_addr == 0)
					{
						vmi_v2pcache_flush(vmi, ~0ull);
						cd_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->cd_in_sshbuf_offset);
					}

					size_t size = _sshhelper->GetSizeT(vmi, dtb, p1+_sshhelper->size_in_sshbuf_offset);
					size_t real_size = size - off;

					size_t max_size = _sshhelper->GetSizeT(vmi, dtb, p1+_sshhelper->max_size_in_sshbuf_offset);

					if(real_size < max_size)
					{
						int payloadOffset = 9;
						char* cd = new char[40];

						_sshhelper->GetChar(vmi, dtb, cd_addr+off+payloadOffset, cd, 40);
						string command = "";
						for(int i = 0 ; i < 40 ; i++)
						{
							command.push_back(cd[i]);
						}

						if(command.find("exec") != string::npos)
						{
							if(command.find("git-receive-pack") != string::npos || command.find("git-upload-pack") != string::npos)
							{
								// cout << "git found" << endl;
								sshchild_git a;
								a.parent_sshd = p.GetPid();
								// a.child_sshd = 0;
								a.git = true;
								a.ip = "0.0.0.0";
								a.repo = "UNKNOWN";
								if(command.find("git-receive-pack") != string::npos)
								{
									a.upload = false;
								}
								else if(command.find("git-upload-pack") != string::npos)
								{
									a.upload = true;
								}
								
								a.child_sshd = p.GetPid();

								sshchild_git_children.push_back(a);
								// cout << "push back " << dec << p.GetPid() << endl;
								// cout << command << endl;
							}
						}
						// cout << "false pid : " << p.GetPid() << endl;
						// cout << hexdumptostring(cd, 40) << endl;

						delete[] cd;
					}

					_sm->Unlock();

					// return false;
				}

				it = find_if(sshchild_git_children.begin(), sshchild_git_children.end(), boost::bind(&sshchild_git::parent_sshd, _1) == p.GetPid());
				if(it == sshchild_git_children.end())
				{
					// cout << "not found " << dec << counting << endl;
					return false;
				}
				else
				{
					// cout << "found " << dec << p.GetPid() << endl;
				}

				vmi_instance_t vmi = _sm->Lock();
				vmi_v2pcache_flush(vmi, ~0ull);
				uint64_t p1 = a->regs.rdi;

				bool ok = false;
				size_t off = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->off_in_sshbuf_offset);
				addr_t cd_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->cd_in_sshbuf_offset);
				if(cd_addr != 0)
				{
					vmi_v2pcache_flush(vmi, ~0ull);
					cd_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->cd_in_sshbuf_offset);
					if(cd_addr != 0)
					{
						ok = true;
					}
				}
				else
				{
					// cout << "cd adr 0 " << dec << counting << endl;
					// cout << "cd adr 0" << endl;
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

							if(payloadSize >= 4)
							{
								string command = "";
								for(int i = 0 ; i < payloadSize ; i++)
								{
									command.push_back(cd[i]);
								}

								if(command.substr(0,4) == "exec")
								{
									// cout << command << endl;

									if(command.find("git-receive-pack") != string::npos || command.find("git-upload-pack") != string::npos)
									{
										if(command.find("git-receive-pack") != string::npos)
										{
											(*it).upload = false;
										}
										else if(command.find("git-upload-pack") != string::npos)
										{
											(*it).upload = true;
										}

										vector<string> tokens;
										split(tokens, command, boost::is_any_of(" "));

										boost::replace_all(tokens.at(1), "'", "");

										(*it).repo = tokens.at(1);

										// cout << (*it).repo << endl;
										// cout << (*it).ip << endl;

										time_t currentTime = chrono::system_clock::now().time_since_epoch() / chrono::milliseconds(1);
										StringBuffer s;
										Writer<StringBuffer> writer(s);
										writer.StartObject();
										writer.Key("repo");
										writer.String((*it).repo.c_str());
										writer.Key("TS");
										writer.Uint64(currentTime);
										writer.Key("ip");
										writer.String((*it).ip.c_str());
										writer.Key("upload");
										writer.Bool((*it).upload);
										writer.Key("function");
										writer.String("BuffGetU8");
										writer.Key("pid");
										writer.Uint64(p.GetPid());
										writer.EndObject();
										(*it).data.push_back(s.GetString());

										// ExecuteQuery("INSERT into repository (name) values ('"+tokens.at(1)+"')");
										// ExecuteQuery("SELECT * from repository where name = '"+tokens.at(1)+"'");
										// cout << "a" << endl;

										// cout << "git" << endl;
										vector<sshchild_git>::iterator it = find_if(sshchild_git_children.begin(), sshchild_git_children.end(), boost::bind(&sshchild_git::child_sshd, _1) == p.GetPid());
										if(it == sshchild_git_children.end())
										{
											(*it).git = true;
										}
									}
								}
								else if(command.find("refs/") != string::npos)
								{
									// cout << "command : " << command << endl;
									if(command.substr(0,4) == "0095" || command.substr(0,4) == "0094" || command.substr(0,4) == "009a")
									{
										vector<string> tokens;
										split(tokens, command, boost::is_any_of(" "));
										// cout << tokens.at(2) << endl;
										// cout << "old : " << tokens.at(0).substr(4) << endl;
										// cout << "new : " << tokens.at(1) << endl;
										time_t currentTime = chrono::system_clock::now().time_since_epoch() / chrono::milliseconds(1);

										uint index = 0;
										string last_ref = "";
										for(vector<string>::iterator it2 = tokens.begin() ; it2 != tokens.end() ; ++it2)
										{
											// cout << (*it2) << endl;
											StringBuffer s;
											Writer<StringBuffer> writer(s);

											if((*it2).substr(0,4) == "0094" || (*it2).substr(0,4) == "0095" || (*it2).substr(0,4) == "009a")
											{
												writer.StartObject();
												writer.Key("repo");
												writer.String((*it).repo.c_str());
												writer.Key("TS");
												writer.Uint64(currentTime);
												writer.Key("ip");
												writer.String((*it).ip.c_str());
												writer.Key("upload");
												writer.Bool((*it).upload);
												writer.Key("refs");
												writer.String(tokens.at(index+2).c_str());
												last_ref = tokens.at(index+2);
												writer.Key("hash");
												writer.String(tokens.at(index+1).c_str());
												writer.Key("hash_old");
												writer.String(tokens.at(index).substr(4).c_str());
												writer.Key("function");
												writer.String("BuffGetU8");
												writer.Key("pid");
												writer.Uint64(p.GetPid());
												writer.EndObject();
												(*it).data.push_back(s.GetString());

												// cout << "in here" << endl;
											}
											else if((*it2).find("refs/") != string::npos && (*it2).find(last_ref) == string::npos)
											{
												int length = (*it2).size();
												// cout <<  << endl;

												writer.StartObject();
												writer.Key("repo");
												writer.String((*it).repo.c_str());
												writer.Key("TS");
												writer.Uint64(currentTime);
												writer.Key("ip");
												writer.String((*it).ip.c_str());
												writer.Key("upload");
												writer.Bool((*it).upload);
												writer.Key("refs");
												if(index == tokens.size() - 1)
												{
													last_ref = (*it2).substr(0, length - 4);
												}
												else
												{
													last_ref = (*it2).substr(0, length - 44);
												}

												writer.String(last_ref.c_str());
												writer.Key("hash");
												writer.String(tokens.at(index-1).c_str());
												writer.Key("hash_old");
												int hash_start = tokens.at(index-2).size() - 40;
												writer.String(tokens.at(index-2).substr(hash_start < 0 ? 0 : hash_start).c_str());
												writer.Key("function");
												writer.String("BuffGetU8");
												writer.Key("pid");
												writer.Uint64(p.GetPid());
												writer.EndObject();
												(*it).data.push_back(s.GetString());

												// cout << "in here 2" << endl;
											}

											index++;
										}
									}
								}
							}

							// cout << hexdumptostring(cd, payloadSize) << endl;
							// get("console")->info("Receive Packet : [{0:d}] size [{1:d}] PID[{3:d}]\n{2}", typep, payloadSize, hexdumptostring(cd, payloadSize), p.GetPid());
							// get("console")->flush();
							delete[] cd;
						}
					}
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
		bool callback(const Event* ev, void* data)
		{
			const ProcessBreakpointEvent* sev = dynamic_cast<const ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
					return false;

				addr_t dtb = a->regs.cr3;
				const Process& p = _pc->GetProcessFromDtb(dtb);
				vector<sshchild_git>::iterator it = find_if(sshchild_git_children.begin(), sshchild_git_children.end(), boost::bind(&sshchild_git::child_sshd, _1) == p.GetPid());
				if(it == sshchild_git_children.end())
				{
					return false;
				}

				// cout << "refs" << endl;
				vmi_instance_t vmi = _sm->Lock();
				vmi_v2pcache_flush(vmi, ~0ull);
				uint64_t p1 = a->regs.rdi;

				if((*it).ip == "0.0.0.0")
				{
					string ip = "0.0.0.0";

					addr_t remote_ip_addr_va = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->remote_ipaddr_in_ssh_offset);
					if(remote_ip_addr_va != 0)
					{
						addr_t remote_ip_addr_pa = _sshhelper->TranslateVaToPa(vmi, dtb, remote_ip_addr_va);
						char* remote_ip = vmi_read_str_pa(vmi, remote_ip_addr_pa);
						ip = string(remote_ip);
						free(remote_ip);
					}

					uint64_t remote_port = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->remote_port_in_ssh_offset);

					(*it).ip = ip;
					UNUSED(remote_port);
				}

				// vmi_pid_t pid = p.GetPid();
				// vmi_pid_t parent = _pc->FindParentProcessPidByPid(pid, _sshd_parent_pid);

				bool ok = false;

				addr_t cd_addr = 0;
				addr_t outGoingPacketAddr = 0;
				uint64_t typep = 0;
				size_t off = 0;

				addr_t state_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->session_state_in_ssh_offset);
				if(state_addr == 0)
				{
					vmi_v2pcache_flush(vmi, ~0ull);
					state_addr = _sshhelper->GetAddrT(vmi, dtb, p1+_sshhelper->session_state_in_ssh_offset);
				}

				if(state_addr != 0)
				{
					outGoingPacketAddr = _sshhelper->GetAddrT(vmi, dtb, state_addr+_sshhelper->outgoing_packet_in_session_state_offset);
					if(outGoingPacketAddr == 0)
					{
						vmi_v2pcache_flush(vmi, ~0ull);
						outGoingPacketAddr = _sshhelper->GetAddrT(vmi, dtb, state_addr+_sshhelper->outgoing_packet_in_session_state_offset);
					}

					if(outGoingPacketAddr != 0)
					{
						off = _sshhelper->GetSizeT(vmi, dtb, outGoingPacketAddr+_sshhelper->off_in_sshbuf_offset);
						cd_addr = _sshhelper->GetAddrT(vmi, dtb, outGoingPacketAddr+_sshhelper->cd_in_sshbuf_offset);
						if(cd_addr == 0)
						{
							vmi_v2pcache_flush(vmi, ~0ull);
							cd_addr = _sshhelper->GetAddrT(vmi, dtb, outGoingPacketAddr+_sshhelper->cd_in_sshbuf_offset);
						}

						if(cd_addr != 0)
						{
							typep = _sshhelper->GetOneByteNumber(vmi, dtb, cd_addr + 5);
							ok = true;
						}
						else
						{
							// cout << "send cd adr 0" << endl;
						}
					}
					else
					{
						// cout << "send out going adr 0" << endl;
					}
				}
				else
				{
					// cout << "state addr adr 0" << endl;
				}

				if(ok)
				{
					//bash only then -> 0, if port forward, bash -> 2 , forward payload -> 3
					// uint64_t packetType = _sshhelper->GetOneByteNumber(vmi, dtb, cd_addr + 9);

					if(typep == 94 || typep == 98)
					{
						size_t size = _sshhelper->GetSizeT(vmi, dtb, outGoingPacketAddr+_sshhelper->size_in_sshbuf_offset);
						size_t real_size = size - off;

						size_t max_size = _sshhelper->GetSizeT(vmi, dtb, outGoingPacketAddr+_sshhelper->max_size_in_sshbuf_offset);

						if(real_size < max_size)
						{
							//get(to_string(parent))->debug("Send Packet : [{0:d}] size [{1:d}]\n", typep, payloadSize);

							if(typep == 94 || typep == 98)
							{
								int payloadOffset = 5+9;
								int payloadSize = real_size-9-5;

								char* cd = new char[payloadSize];

								_sshhelper->GetChar(vmi, dtb, cd_addr+payloadOffset, cd, payloadSize);

								string command = "";
								for(int i = 0 ; i < payloadSize ; i++)
								{
									command.push_back(cd[i]);
								}

								// cout << command << endl;

								if(command.find("exit-status") != string::npos)
								{
									// cout << "exit-status " << dec << p.GetPid() << endl;
									_el->BulkInsert("git-monitoring", (*it).data);

									// for(vector<string>::iterator it2 = (*it).data.begin() ; it2 != (*it).data.end() ; ++it2)
									// {
									// 	cout << (*it2) << endl;
									// }

									for(vector<sshchild_git>::iterator it3 = sshchild_git_children.begin(); it3 != sshchild_git_children.end();)
									{
										if((*it3).child_sshd == p.GetPid())
										{
											it3 = sshchild_git_children.erase(it3);
										}
										else
										{
											++it3;
										}
									}
								}
								else if(command.find("refs/") != string::npos)
								{
									if(command.find("agent=") == string::npos && command.find("eunpack") == string::npos)
									{
										// cout << "in" << endl;
										vector<string> tokens1;
										split(tokens1, command, boost::is_any_of("\n"));

										// uint index = 0;
										time_t currentTime = chrono::system_clock::now().time_since_epoch() / chrono::milliseconds(1);
										for(vector<string>::iterator it2 = tokens1.begin() ; it2 != tokens1.end() ; ++it2)
										{
											// cout << (*it2) << endl;
											vector<string> tokens;
											split(tokens, (*it2), boost::is_any_of(" "));
											// cout << dec << tokens.size() << endl;

											if(tokens.size() < 2)
												break;

											StringBuffer s;
											Writer<StringBuffer> writer(s);
											writer.StartObject();
											writer.Key("repo");
											writer.String((*it).repo.c_str());
											writer.Key("TS");
											writer.Uint64(currentTime);
											writer.Key("ip");
											writer.String((*it).ip.c_str());
											writer.Key("upload");
											writer.Bool((*it).upload);
											writer.Key("refs");
											writer.String(tokens.at(1).c_str());
											writer.Key("hash");
											writer.String(tokens.at(0).substr(4).c_str());
											writer.Key("function");
											writer.String("PacketSend2Wrapped");
											writer.Key("pid");
											writer.Uint64(p.GetPid());

											if((*it).upload)
											{
												string result = _el->Query("git-monitoring", "repo:\""+ (*it).repo +"\" AND upload:false AND refs: \""+tokens.at(1)+"\"", "1", "TS:desc");
												// cout << "res : " << result << endl;

												Document doc;
												doc.Parse(result.c_str());
												if(!doc.HasParseError())
												{
													if(doc.HasMember("hits"))
													{
														if(doc["hits"].HasMember("total"))
														{
															if(doc["hits"]["total"].GetInt() > 0)
															{
																try
																{
																	string hash_db = doc["hits"]["hits"][0]["_source"]["hash"].GetString();
																	// cout << tokens.at(1).c_str() << " = " << tokens.at(0).substr(4) << " * " << hash_db << endl;
																	if(tokens.at(0).substr(4) != hash_db)
																	{
																		// (*it).inconsistent = true;
																		// cout << "inconsistent" << endl;
																		(*it).inconsistent.push_back(tokens.at(1).c_str());
																		writer.Key("inconsistent");
																		writer.Bool(true);
																	}
																	else
																	{
																		writer.Key("inconsistent");
																		writer.Bool(false);
																	}
																}
																catch(...)
																{

																}
															}
														}
													}
												}
											}

											writer.EndObject();
											(*it).data.push_back(s.GetString());
										}
									}
									else
									{

									}
								}
								else if(command.find("002d") != string::npos)
								{
									// cout << (*it).inconsistent << endl;
									if((*it).inconsistent.size() > 0)
									{
										string aaa = "WARNING!!! inconsistent state";
										int n = aaa.length() + 1;
										char* payload = new char[n];
										strcpy(payload, aaa.c_str());
										vmi_write_va(vmi, cd_addr + payloadOffset + 5, p.GetPid(), n, payload, NULL);
										delete[] payload;
									}
								}

								// cout << hexdumptostring(cd, payloadSize) << endl;
								// get("console")->info("Sent Packet : [{0:d}] size [{1:d}] PID[{3:d}]\n{2}", typep, payloadSize, hexdumptostring(cd, payloadSize), p.GetPid());
								// get("console")->flush();

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

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		cout << argv[0] << " <vmname> <setting json>" << endl;
		return -1;
	}

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

	Setting setting(argv[2]);
	_sshd_bin_path = setting.GetStringValue("sshd_bin_path");
	_sshd_path = setting.GetStringValue("sshd_path");
	_bp_type = setting.GetIntValue("bp_type");
	_es_path = setting.GetStringValue("es_path");
	_ip = setting.GetStringValue("ip");

	_el = new ElasticLogger(_es_path);
	if(!_el->CheckIndex("git-monitoring"))
	{
		_el->CreateIndex("git-monitoring", "\"mappings\":{\"doc\":{\"properties\":{\"TS\":{\"type\":\"date\"},\"ip\":{\"type\":\"ip\"}}}}");
	}

	SystemMonitor sm(argv[1], true);
	_sm = &sm;

	Altp2mBasic* altp2mbasic = new Altp2mBasic(sm);
	sm.SetBPM(altp2mbasic, altp2mbasic->GetType());
	sm.Init();
	altp2mbasic->Init();

	// Int3* int3 = new Int3(sm);
	// sm.SetBPM(int3, int3->GetType());
	// sm.Init();
	// int3->Init();

	// RegisterMechanism rm(sm);
	// sm.SetRM(&rm);
	sm.Loop();

	LinuxVM linux(&sm);
	_linux = &linux;

	ProcessCache pc(linux);
	_pc = &pc;

	SSHHelper sshhelper(_sshd_bin_path, _ip);
	sshhelper.GetOffsets();
	_sshhelper = &sshhelper;

	// int rc = sqlite3_open("database.db", &db);

	// vector<string> queries;
	// queries.push_back("CREATE TABLE repository (name text NOT NULL, UNIQUE(name))");

	// for(vector<string>::iterator it = queries.begin() ; it != queries.end(); ++it)
	// {
	// 	string tmp = *it;
	// 	if(!ExecuteQuery(tmp))
	// 	{
	// 		break;
	// 	}
	// }

	// UNUSED(rc);
	// cout << rc << endl;

	if(FindSSHDParent())
	{
		vmi_instance_t vmi = sm.Lock();
		addr_t xen_interrupt_va = 0;
		addr_t xen_interrupt_pa = 0;
		vmi_translate_ksym2v(vmi, (char*)"xen_hvm_callback_vector", &xen_interrupt_va);
		vmi_translate_kv2p(vmi, xen_interrupt_va, &xen_interrupt_pa);
		sm.AddExludeAddress(xen_interrupt_pa);
		sm.Unlock();

		buffGetU8Listener = new BuffGetU8Listener();
		ProcessBreakpointEvent* buffGetU8Event = new ProcessBreakpointEvent("SSHBuffGetU8Listener", 0, sshhelper.sshbuf_get_u8_pa, *buffGetU8Listener);
		sm.GetBPM()->InsertBreakpoint(buffGetU8Event);

		packetSend2WrappedListener = new PacketSend2WrappedListener();
		ProcessBreakpointEvent* packetSend2WrappedEvent = new ProcessBreakpointEvent("PacketSend2WrappedListener", 0, sshhelper.ssh_packet_send2_wrapped_pa, *packetSend2WrappedListener);
		sm.GetBPM()->InsertBreakpoint(packetSend2WrappedEvent);

		cloneListener = new CloneListener();
		SyscallEvent* cloneS = new SyscallEvent(56, *cloneListener, true, false, false);
		// linux.RegisterSyscall(*cloneS);
		UNUSED(cloneS);
	}
	else
	{
		interrupted = true;
	}

	while(!interrupted) 
	{
		sleep(1);
	}

	// if(db)
	// {
	// 	sqlite3_close(db);
	// }

	linux.Stop();
	sm.Stop();

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
			cout << dec << "parent sshd : " << _sshd_parent_pid << endl;
			_sshhelper->GetAddresses(_linux, (*it));

			return true;
		}
	}

	return false;
}
