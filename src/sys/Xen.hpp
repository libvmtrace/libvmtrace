#ifndef __XEN_H_
#define __XEN_H_

#include <iostream>
#include <stdexcept>
#include <dlfcn.h>
#include <libvmi/libvmi.h>

extern "C"
{
	#include <xenctrl.h>
}

namespace libvmtrace
{
	// https://github.com/xen-project/xen/blob/16bbf8e7b39b50457bb2f6547f166bd54d50e4cd/tools/libxc/include/xenctrl.h
	class Xen
	{
	public:
		Xen(uint64_t vmid);
		~Xen();

		status_t CreateNewPage(uint64_t *addr);
		status_t DestroyPage(uint64_t *addr);
		void GetMaxGFN(uint64_t *max_gfn);
		uint64_t GetMaxMem()
		{
			return _max_mem;
		};
		void SetMaxMem(uint64_t mem);

	private:
		uint64_t _vmid;
		uint64_t _max_mem;
		xc_interface* _xci;
	};
}

#endif

