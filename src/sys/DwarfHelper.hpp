
#ifndef __DWARFHELPER_H__
#define __DWARFHELPER_H__

#include <libdwarfparser/libdwarfparser.h>
#include <libvmi/libvmi.h>

namespace libvmtrace
{
	class DwarfHelper 
	{
		public:
			DwarfHelper(std::string binaryPath);
			addr_t getVariableOffset(std::string structName, std::string variableName);
		
		private:
			SymbolManager _mgr;
			BaseType *_bt;
			Struct *_structPtr;
			std::string _structNameTemp;
	};
}

#endif
