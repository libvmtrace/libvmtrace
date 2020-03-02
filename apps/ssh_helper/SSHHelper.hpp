
#ifndef __SSH_HELPER_HH_
#define __SSH_HELPER_HH_

#include <string>
#include <libssh/libssh.h>
#include <libvmtrace.hpp>
#include <sys/LinuxVM.hpp>

namespace helpers
{
	struct sshchild
	{
		vmi_pid_t pid;
		addr_t sshAddr;
		time_t lastPacketSend;
		vmi_pid_t sub_pid;
		string username;
		int tmp;
		int authPass;
		bool portForward;
	};

	struct writefile
	{
		vmi_pid_t pid;
		vmi_pid_t parent;
		string name;
		string path;
		uint64_t fd;
		bool fseek;
		off_t offset;
	};

	struct writefind
	{
		vmi_pid_t pid;
		vmi_pid_t parent;
		uint64_t fd;
		string path;
		bool checkpath;

		writefind(vmi_pid_t pid,vmi_pid_t parent,uint64_t fd) : pid(pid),parent(parent),fd(fd),path(""),checkpath(false){}
		writefind(vmi_pid_t pid,vmi_pid_t parent,uint64_t fd,string path) : pid(pid),parent(parent),fd(fd),path(path.empty() ? "EMPTY" : path),checkpath(true){}

		bool operator()(const writefile& j) const 
		{
			if(!checkpath)
				return (j.pid == pid && j.parent == parent && j.fd == fd);
			else
				return (j.pid == pid && j.parent == parent && j.fd == fd && j.path == path);
		}
	};

	class PageFaultListener : public EventListener
	{
		public:
			bool callback(const Event* ev, void* data)
			{
				return true;
			}
	};

	class SSHHelper
	{
		public:
			SSHHelper(const std::string binary_path, const string ip) : _binary_path(binary_path), _ip(ip)
			{
				_ctx_dtb.translate_mechanism = VMI_TM_PROCESS_DTB;
			};
			
			void GetOffsets();

			void GetAddresses(libvmtrace::LinuxVM* lvm, libvmtrace::Process& p);

			void OpenSSHConnection();

			addr_t GetAddrT(vmi_instance_t vmi, addr_t dtb, addr_t vaddr);
			size_t GetSizeT(vmi_instance_t vmi, addr_t dtb, addr_t vaddr);
			uint64_t GetOneByteNumber(vmi_instance_t vmi, addr_t dtb, addr_t vaddr);
			status_t GetChar(vmi_instance_t vmi, addr_t dtb, addr_t vaddr, void *buf, size_t count);

			addr_t TranslateVaToPa(vmi_instance_t vmi, addr_t dtb, addr_t vaddr);

			addr_t user_in_authctxt_offset;
			addr_t valid_in_authctxt_offset;
			addr_t failures_in_authctxt_offset;
			addr_t remote_ipaddr_in_ssh_offset;
			addr_t remote_port_in_ssh_offset;
			addr_t kex_in_ssh_offset;
			addr_t session_state_in_ssh_offset;
			addr_t outgoing_packet_in_session_state_offset;
			addr_t newkeys_in_kex_offset;
			addr_t enc_in_newkeys_offset;
			addr_t mac_in_newkeys_offset;
			addr_t comp_in_newkeys_offset;
			addr_t name_in_enc_offset;
			addr_t key_len_in_enc_offset;
			addr_t key_in_enc_offset;
			addr_t iv_len_in_enc_offset;
			addr_t iv_in_enc_offset;
			addr_t block_size_in_enc_offset;
			addr_t name_in_mac_offset;
			addr_t key_len_in_mac_offset;
			addr_t key_in_mac_offset;
			addr_t name_in_comp_offset;
			addr_t newkeys_in_session_state_offset;
			addr_t size_in_sshbuf_offset;
			addr_t max_size_in_sshbuf_offset;
			addr_t off_in_sshbuf_offset;
			addr_t cd_in_sshbuf_offset;
			addr_t receive_context_in_session_state_offset;
			addr_t send_context_in_session_state_offset;
			addr_t sshcipher_in_sshcipher_ctx_offset;
			addr_t iv_len_in_sshcipher;
			addr_t key_len_in_sshcipher;
			addr_t block_size_in_sshcipher;

			addr_t auth_password_va;
			addr_t kex_derive_keys_va;
			addr_t do_authentiation2_va;
			addr_t sshbuf_get_u8_va;
			addr_t ssh_packet_send2_wrapped_va;
			addr_t channel_connect_to_port_va;

			addr_t auth_password_pa;
			addr_t kex_derive_keys_pa;
			addr_t do_authentiation2_pa;
			addr_t sshbuf_get_u8_pa;
			addr_t ssh_packet_send2_wrapped_pa;
			addr_t channel_connect_to_port_pa;

		private:
			const std::string _binary_path;
			const std::string _ip;
			ssh_session _ssh_session;

			access_context_t _ctx_dtb;

			PageFaultListener _pfl;
	};
}

#endif

