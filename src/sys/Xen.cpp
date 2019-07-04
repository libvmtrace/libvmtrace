#include "sys/Xen.hpp"

Xen::Xen(uint64_t vmid) : _vmid(vmid)
{
	_xci = xc_interface_open(NULL, NULL, 0);
	xc_dominfo_t info = { 0 };
	if (xc_domain_getinfo(_xci, vmid, 1, &info) && info.domid == vmid)
	{
		_max_mem = info.max_memkb;
	}
	else
	{
		_max_mem = 0;
	}
}

Xen::~Xen()
{
	xc_interface_close(_xci);
}

status_t Xen::CreateNewPage(uint64_t *addr)
{
	int rc = xc_domain_populate_physmap_exact(_xci, _vmid, 1, 0, 0, addr);
	if(rc < 0)
	{
		return VMI_FAILURE;
	}
	else
	{
		return VMI_SUCCESS;
	}
}

status_t Xen::DestroyPage(uint64_t *addr)
{
	int rc = xc_domain_decrease_reservation_exact(_xci, _vmid, 1, 0, addr);
	if(rc < 0)
	{
		return VMI_FAILURE;
	}
	else
	{
		return VMI_SUCCESS;
	}
}

void Xen::GetMaxGFN(uint64_t *max_gfn)
{
	xc_domain_maximum_gpfn(_xci, _vmid, max_gfn);
}

void Xen::SetMaxMem(uint64_t mem)
{
	xc_domain_setmaxmem(_xci, _vmid, mem);
}