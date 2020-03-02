
#include <sys/DwarfHelper.hpp>

namespace libvmtrace
{
	DwarfHelper::DwarfHelper(std::string binaryPath)
	{
		DwarfParser::parseDwarfFromFilename(binaryPath.c_str(), &_mgr);
		_structNameTemp = "";
	}

	addr_t DwarfHelper::getVariableOffset(std::string structName, std::string variableName)
	{
		if(_structNameTemp.compare(structName) != 0)
		{
			_bt = _mgr.findBaseTypeByName<Structured>(structName);
			_structPtr = dynamic_cast<Struct *>(_bt);
			_structNameTemp = structName;
		}
		
		return _structPtr->memberOffset(variableName);
	}
}

