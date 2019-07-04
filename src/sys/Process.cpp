#include "sys/Process.hpp"

Value Process::ToJson(Document::AllocatorType& allocator) 
{
	Value value;
	value.SetObject();

	Value temp;
	temp = StringRef(_name.c_str());
	value.AddMember("process_name",temp,allocator);
	value.AddMember("pid",_pid,allocator);
	value.AddMember("uid",_uid,allocator);
	temp = StringRef(int_to_hex(_dtb).c_str());
	value.AddMember("dtb",temp,allocator);
	temp = StringRef(int_to_hex(_task_struct).c_str());
	value.AddMember("task_struct",temp,allocator);
	value.AddMember("parent",_parent_pid,allocator);

	return value;
}