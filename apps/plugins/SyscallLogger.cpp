
#include <plugins/SyscallLogger.hpp>

using namespace rapidjson;

namespace libvmtrace
{
	const std::string SyscallLogger::ExecuteCommand(const std::string command, 
					const std::vector<std::string> params,
					const std::string command_id,
					const std::string vm_id)
	{
		if(vm_id != _vm_id)
		{
			return "";
		}

		if(command == "Trace" && params.size() > 0)
		{
			for(auto x : params)
			{
				int nr = atoi(x.c_str());
				if (_events[nr] == NULL)
				{
					if(nr == 59) // exec does not return
					{	
						_events[nr] = new SyscallEvent(nr, *this, false, false, _json);
					}
					else
					{
						_events[nr] = new SyscallEvent(nr, *this, _return_value, false, _json);
					}

					_os.RegisterSyscall(*_events[nr]);
				}
			}
		}
		else if(command == "Untrace" && params.size() > 0)
		{
			for(auto x : params)
			{
				int nr = atoi(x.c_str());
				if(_events[nr] != nullptr)
				{
					_os.DeRegisterSyscall(*_events[nr]);
					delete _events[nr];
					_events[nr] = nullptr;
				}
			}
		}

		return "";
	}

	bool SyscallLogger::callback(Event* ev, void* data)
	{
		const SyscallEvent* sev = dynamic_cast<const SyscallEvent*>(ev);

		if(!sev)
		{
			return  false;
		}
		SyscallBasic* s = (SyscallBasic*)data;


		std::string json = s->ToJson();
	//	if (json.length() == 2) 
	//		return false;

		Document document;
		document.Parse(json.c_str());
		Document::AllocatorType& allocator = document.GetAllocator();


	// #if 0
		try
		{
			const Process& p = _pc.GetProcessFromDtb(s->GetDtb());
			std::string name = p.GetName();
			std::string pwd = p.GetPwd();

			// Value sa;
			// sa = StringRef(name.c_str());

			document.AddMember("proc_name", Value(name.c_str(), allocator).Move(), allocator);
			document.AddMember("uid", p.GetUid(), allocator);

			// sa = StringRef(pwd.c_str());
			document.AddMember("pwd",  Value(pwd.c_str(), allocator).Move(), allocator);
		}
		catch(...)
		{
			document.AddMember("proc_name", "ERR", allocator);
			document.AddMember("uid", 0, allocator);
			document.AddMember("pwd", "ERR", allocator);
		}

		if(s->GetNr() == 2)
		{
			std::string path = "EMPTY PATH";
			std::string pwd = "EMPTY PWD";
			if (document.HasMember("path"))
			    path = document["path"].GetString();
			if (document.HasMember("pwd"))
			    pwd = document["pwd"].GetString();

			std::string fullPath = path;
			if(!path.empty())
			{
				std::string tmp = path.substr(0,1);
				if(tmp.compare("/") != 0)
				{
					fullPath = pwd+"/"+path;
				}
			}

			Value sa;
			sa = StringRef(fullPath.c_str());
			document.AddMember("fullPath", sa, allocator);
		}
	// #endif

		StringBuffer strbuf;
		Writer<StringBuffer> writer(strbuf);
		document.Accept(writer);

		_log.log(_vm_id, _log_name, strbuf.GetString());

		return false;
	}
}

