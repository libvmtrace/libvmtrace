#include "sys/DwarfHelper.hpp"

DwarfHelper::DwarfHelper(string binaryPath)
{
	DwarfParser::parseDwarfFromFilename(binaryPath.c_str(), &_mgr);
	_structNameTemp = "";
}

addr_t DwarfHelper::getVariableOffset(string structName, string variableName)
{
	if(_structNameTemp.compare(structName) != 0)
	{
		_bt = _mgr.findBaseTypeByName<Structured>(structName);
		_structPtr = dynamic_cast<Struct *>(_bt);
		_structNameTemp = structName;
	}
	
	return _structPtr->memberOffset(variableName);
}