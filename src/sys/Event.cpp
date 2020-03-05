
#include <sys/Event.hpp>

namespace libvmtrace
{
	template<typename U, typename T>
	void EventManager<U, T>::RegisterEvent(U signal, T e)
	{
		RemoveEvents();
		typename evmap::iterator it =  _Events.find(signal);

		if (it == _Events.end() ) {
			std::pair<typename evmap::iterator,bool> ret;

			ret =  _Events.insert(std::pair<U, std::vector<T>>(signal, std::vector<T>()));
			it = ret.first;
		} 
		it->second.push_back(e);
		
	}

	template<typename U, typename T>
	void EventManager<U, T>::DeRegisterEvent(U signal, T e)
	{
		_DeleteEvents.push_back(std::pair<U, T>(signal,e));
	}

	template<typename U, typename T>
	void EventManager<U, T>::Call(U signal, void* data)
	{
		RemoveEvents();

		typename std::map<U, std::vector<T>>::iterator it =  _Events.find(signal);
		typename std::vector<T>::iterator listit;

		for (listit=it->second.begin(); listit!=it->second.end(); ++listit)
		{
			T event = (*listit);
			if(event != nullptr && event->callback(data) == true)
				DeRegisterEvent(signal, event);
		}

		RemoveEvents();
	}

	template<typename U, typename T>
	uint64_t EventManager<U, T>::GetCount(U signal)
	{
		RemoveEvents();
		typename std::map<U, std::vector<T>>::iterator it =  _Events.find(signal);
		if (it == _Events.end() )
			return 0;
		return it->second.size();
	}

	template<typename U, typename T>
	void EventManager<U, T>::ForEach(void(*f)(T e, void*), void* data)
	{
		RemoveEvents();
		typename std::map<U, std::vector<T>>::iterator mapit ;

		for (mapit =  _Events.begin(); mapit != _Events.end(); ++mapit) {
			typename std::vector<T>::iterator listit;
			for (listit = mapit->second.begin(); listit!= mapit->second.end(); listit++) {
				T event = (*listit);
				f(event, data);
			}
		}    
	}

	template<typename U, typename T>
	void EventManager<U, T>::RemoveEvents()
	{
		for (typename std::vector<std::pair<U, T>>::iterator it = _DeleteEvents.begin() ; it != _DeleteEvents.end();)
		{
			uint64_t signal = (*it).first;
			T ev = (*it).second;

			typename std::map<U, std::vector<T>>::iterator mapit =  _Events.find(signal);
			if (mapit != _Events.end() ) {
				mapit->second.erase(remove(mapit->second.begin(), mapit->second.end(), ev), mapit->second.end()); 

				if (mapit->second.size() == 0)
					_Events.erase(signal);
			}

			it = _DeleteEvents.erase(it);
		}

		assert (_DeleteEvents.size() == 0);
	}

	template class EventManager<int, const ProcessBreakpointEvent*>;
	template class EventManager<int, const SyscallEvent*>;
	template class EventManager<uint64_t, const MemEvent*>;
	template class EventManager<uint64_t, const BreakpointEvent*>;
	template class EventManager<uint64_t, const RegEvent*>;
	template class EventManager<register_t, const RegEvent*>;
}

