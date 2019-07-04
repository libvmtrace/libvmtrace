#include "ssh_helper/SSHHelper.hpp"

addr_t SSHHelper::GetAddrT(vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
	addr_t ret = 0;

	_ctx_dtb.dtb = dtb;
	_ctx_dtb.addr = vaddr;

	if(vmi_read(vmi, &_ctx_dtb, sizeof(addr_t), &ret, NULL) == VMI_FAILURE)
	{
		return 0;
	}

	return ret;
}

addr_t SSHHelper::GetSizeT(vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
	addr_t ret = 0;

	_ctx_dtb.dtb = dtb;
	_ctx_dtb.addr = vaddr;

	if(vmi_read(vmi, &_ctx_dtb, sizeof(size_t), &ret, NULL) == VMI_FAILURE)
	{
		return 0;
	}

	return ret;
}

addr_t SSHHelper::GetOneByteNumber(vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
	addr_t ret = 0;
 
	_ctx_dtb.dtb = dtb;
	_ctx_dtb.addr = vaddr;

	if(vmi_read(vmi, &_ctx_dtb, 1, &ret, NULL) == VMI_FAILURE)
	{
		return 0;
	}

	return ret;
}

addr_t SSHHelper::TranslateVaToPa(vmi_instance_t vmi, addr_t dtb, addr_t vaddr)
{
	addr_t ret = 0;

	if(vmi_pagetable_lookup(vmi, dtb, vaddr, &ret) == VMI_FAILURE)
	{
		return 0;
	}

	return ret;
}

status_t SSHHelper::GetChar(vmi_instance_t vmi, addr_t dtb, addr_t vaddr, void *buf, size_t count)
{ 
	_ctx_dtb.dtb = dtb;
	_ctx_dtb.addr = vaddr;

	if(vmi_read(vmi, &_ctx_dtb, count, buf, NULL) == VMI_FAILURE)
	{
		return VMI_FAILURE;
	}

	return VMI_SUCCESS;
}

void SSHHelper::OpenSSHConnection()
{
	int rc;
	_ssh_session = ssh_new();
	if(_ssh_session == NULL)
	{
		cerr << "unable to create ssh" << endl;
		return;
	}

	ssh_options_set(_ssh_session, SSH_OPTIONS_HOST, _ip.c_str());
	ssh_options_set(_ssh_session, SSH_OPTIONS_USER, "root");
	rc = ssh_connect(_ssh_session);
	if(rc != SSH_OK)
	{
		cout << "ssh connect error : " << ssh_get_error(_ssh_session) << endl;
	}

	rc = ssh_userauth_password(_ssh_session, NULL, "1234");
	if(rc != SSH_AUTH_SUCCESS)
	{
		cout << "ssh auth error : " << ssh_get_error(_ssh_session) << endl;
	}

	ssh_disconnect(_ssh_session);
	ssh_free(_ssh_session);
}

void SSHHelper::GetAddresses(LinuxVM* lvm, Process& p)
{
	//SystemMonitor* sm = lvm->GetSystemMonitor();
	//vmi_instance_t vmi = sm->Lock();

	auth_password_va = lvm->GetSymbolAddrVa(_binary_path, p, "auth_password");
	kex_derive_keys_va = lvm->GetSymbolAddrVa(_binary_path, p, "kex_derive_keys");
	do_authentiation2_va = lvm->GetSymbolAddrVa(_binary_path, p, "do_authentication2");
	sshbuf_get_u8_va = lvm->GetSymbolAddrVa(_binary_path, p, "sshbuf_get_u8");
	ssh_packet_send2_wrapped_va = lvm->GetSymbolAddrVa(_binary_path, p, "ssh_packet_send2_wrapped");
	channel_connect_to_port_va = lvm->GetSymbolAddrVa(_binary_path, p, "channel_connect_to_port");

	auth_password_pa = lvm->GetSymbolAddrPa(_binary_path, p, "auth_password");
	if(auth_password_pa == 0)
	{
		cout << "Page fault : auth_password_pa" << endl;
		lvm->PopulatePageFaultAdress(p.GetPid(), kex_derive_keys_va, &_pfl);
	}

	kex_derive_keys_pa = lvm->GetSymbolAddrPa(_binary_path, p, "kex_derive_keys");
	if(kex_derive_keys_pa == 0)
	{
		cout << "Page fault : kex_derive_keys_pa" << endl;
		lvm->PopulatePageFaultAdress(p.GetPid(), kex_derive_keys_va, &_pfl);
	}

	do_authentiation2_pa = lvm->GetSymbolAddrPa(_binary_path, p, "do_authentication2");
	if(do_authentiation2_pa == 0)
	{
		cout << "Page fault : do_authentiation2_pa" << endl;
		lvm->PopulatePageFaultAdress(p.GetPid(), do_authentiation2_va, &_pfl);
	}

	sshbuf_get_u8_pa = lvm->GetSymbolAddrPa(_binary_path, p, "sshbuf_get_u8");
	if(sshbuf_get_u8_pa == 0)
	{
		cout << "Page fault : sshbuf_get_u8_pa" << endl;
		lvm->PopulatePageFaultAdress(p.GetPid(), sshbuf_get_u8_va, &_pfl);
	}

	ssh_packet_send2_wrapped_pa = lvm->GetSymbolAddrPa(_binary_path, p, "ssh_packet_send2_wrapped");
	if(ssh_packet_send2_wrapped_pa == 0)
	{
		cout << "Page fault : ssh_packet_send2_wrapped_pa" << endl;
		lvm->PopulatePageFaultAdress(p.GetPid(), ssh_packet_send2_wrapped_va, &_pfl);
	}

	channel_connect_to_port_pa = lvm->GetSymbolAddrPa(_binary_path, p, "channel_connect_to_port");
	if(channel_connect_to_port_pa == 0)
	{
		cout << "Page fault : channel_connect_to_port_pa" << endl;
		lvm->PopulatePageFaultAdress(p.GetPid(), channel_connect_to_port_va, &_pfl);
	}

	lvm->InvokePageFault(2);

	OpenSSHConnection();
	auth_password_pa = lvm->GetSymbolAddrPa(_binary_path, p, "auth_password");
	kex_derive_keys_pa = lvm->GetSymbolAddrPa(_binary_path, p, "kex_derive_keys");
	do_authentiation2_pa = lvm->GetSymbolAddrPa(_binary_path, p, "do_authentication2");
	sshbuf_get_u8_pa = lvm->GetSymbolAddrPa(_binary_path, p, "sshbuf_get_u8");
	ssh_packet_send2_wrapped_pa = lvm->GetSymbolAddrPa(_binary_path, p, "ssh_packet_send2_wrapped");
	channel_connect_to_port_pa = lvm->GetSymbolAddrPa(_binary_path, p, "channel_connect_to_port");

	//sm->Unlock();
}

void SSHHelper::GetOffsets()
{
	DwarfHelper df(_binary_path);

	user_in_authctxt_offset = df.getVariableOffset("Authctxt","user");
	valid_in_authctxt_offset = df.getVariableOffset("Authctxt","valid");
	failures_in_authctxt_offset = df.getVariableOffset("Authctxt","failures");

	remote_ipaddr_in_ssh_offset = df.getVariableOffset("ssh","remote_ipaddr");
	remote_port_in_ssh_offset = df.getVariableOffset("ssh","remote_port");
	kex_in_ssh_offset = df.getVariableOffset("ssh","kex");
	session_state_in_ssh_offset = df.getVariableOffset("ssh","state");
	
	outgoing_packet_in_session_state_offset = df.getVariableOffset("session_state","outgoing_packet");
	
	newkeys_in_kex_offset = df.getVariableOffset("kex","newkeys");

	enc_in_newkeys_offset = df.getVariableOffset("newkeys","enc");
	mac_in_newkeys_offset = df.getVariableOffset("newkeys","mac");
	comp_in_newkeys_offset = df.getVariableOffset("newkeys","comp");

	name_in_enc_offset = df.getVariableOffset("sshenc","name");
	key_len_in_enc_offset = df.getVariableOffset("sshenc","key_len");
	key_in_enc_offset = df.getVariableOffset("sshenc","key");
	iv_len_in_enc_offset = df.getVariableOffset("sshenc","iv_len");
	iv_in_enc_offset = df.getVariableOffset("sshenc","iv");
	block_size_in_enc_offset = df.getVariableOffset("sshenc","block_size");

	name_in_mac_offset = df.getVariableOffset("sshmac","name");
	key_len_in_mac_offset = df.getVariableOffset("sshmac","key_len");
	key_in_mac_offset = df.getVariableOffset("sshmac","key");

	name_in_comp_offset = df.getVariableOffset("sshcomp","name");

	newkeys_in_session_state_offset = df.getVariableOffset("session_state","newkeys");

	size_in_sshbuf_offset = df.getVariableOffset("sshbuf","size");
	max_size_in_sshbuf_offset = df.getVariableOffset("sshbuf","max_size");
	off_in_sshbuf_offset = df.getVariableOffset("sshbuf","off");
	cd_in_sshbuf_offset = df.getVariableOffset("sshbuf","cd");

	receive_context_in_session_state_offset = df.getVariableOffset("session_state","receive_context");
	send_context_in_session_state_offset = df.getVariableOffset("session_state","send_context");
	sshcipher_in_sshcipher_ctx_offset = df.getVariableOffset("sshcipher_ctx","cipher");

	iv_len_in_sshcipher = df.getVariableOffset("sshcipher","iv_len");
	key_len_in_sshcipher = df.getVariableOffset("sshcipher","key_len");
	block_size_in_sshcipher = df.getVariableOffset("sshcipher","block_size");
}