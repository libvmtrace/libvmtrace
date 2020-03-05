
#ifndef __PERIODIC_TIMER_H__
#define __PERIODIC_TIMER_H__

#include <thread>
#include <chrono>
#include <functional>
#include <unistd.h>
#include <chrono>

namespace libvmtrace
{
namespace util
{
	static void PThelper(class PeriodicTimer* p);

	class PeriodicTimer
	{
	public:
		PeriodicTimer(std::function<void(void*)> f, void* data, int time_ms) : _stop(false), _func(f), _data(data), _time_ms(time_ms)
		{
			try
			{
				_worker = std::thread(PThelper, this);
			}
			catch(...)
			{
				std::cerr << "Could not start PeriodicTimer Worker " << std::endl;
			}
		}

		~PeriodicTimer()
		{
			_stop = true;
			_worker.join();
		}

		void loop()
		{
			while (!_stop)
			{
				auto start = std::chrono::high_resolution_clock::now();
				
				try
				{
					_func(_data);
				}
				catch(...)
				{
					std::cerr << "Could not call PeriodicTimer Callback" << std::endl;
				}

				auto end = std::chrono::high_resolution_clock::now();
				auto dur = end - start;
	                        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();

				if (_time_ms - ms > 0)
					std::this_thread::sleep_for(std::chrono::milliseconds(_time_ms - ms));
				else
				{
					std::cerr << "periodic timer: time too low " << ms << " < " << _time_ms << std::endl;
					std::this_thread::sleep_for(std::chrono::milliseconds(_time_ms));
				}
			}
		}

	private:
		bool _stop;
		std::function<void(void*)> _func;
		void* _data;
		int _time_ms;
		std::thread _worker;
	};

	static void PThelper(class PeriodicTimer* p) { p->loop(); }
}
}

#endif

