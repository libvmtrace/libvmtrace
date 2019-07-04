#ifndef __DWARFHELPER_H__
#define __DWARFHELPER_H__

#include <libdwarfparser/libdwarfparser.h>
#include <libvmi/libvmi.h>

using namespace std;

class DwarfHelper 
{
	public:
		DwarfHelper(string binaryPath);
		addr_t getVariableOffset(string structName, string variableName);
	private:
		SymbolManager _mgr;
		BaseType *_bt;
		Struct *_structPtr;
		string _structNameTemp;
};

#endif