
#include <sys/OperatingSystem.hpp>

using namespace rapidjson;

namespace libvmtrace
{
	std::string OperatingSystem::GetProcessesListJson(std::vector<Process> processes)
	{
		Document document;
		document.SetObject();
		Document::AllocatorType& allocator = document.GetAllocator();
		Value array(kArrayType);

		for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
		{
			array.PushBack((*it).ToJson(allocator), allocator);
		}

		document.AddMember("processes", array, allocator);
		StringBuffer s;
		Writer<StringBuffer> writer(s);
		document.Accept(writer);

		return s.GetString();
	}
}

