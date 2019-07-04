#ifndef __PERIODIC_TIMER_H__
#define __PERIODIC_TIMER_H__

#include <thread>
#include <chrono>
#include <functional>
#include <unistd.h>
#include <chrono>


using namespace std;

class PeriodicTimer;

static void PThelper(PeriodicTimer* p);

class PeriodicTimer
{
	public:
		PeriodicTimer(function<void(void*)> f, void* data, int time_ms) : _stop(false), _func(f), _data(data), _time_ms(time_ms)
		{
			try
			{
				_worker = thread(PThelper, this);
			}
			catch(...)
			{
				cerr << "Could not start PeriodicTimer Worker " << endl;
			}
		}

		~PeriodicTimer()
		{
			_stop = true;
			_worker.join();
		}

		void loop()
		{
			while(!_stop)
			{
				auto start = std::chrono::high_resolution_clock::now();
				try
				{
					_func(_data);
				}
				catch(...)
				{
					cerr << "Could not call PeriodicTimer Callback" << endl;
				}
				auto end = std::chrono::high_resolution_clock::now();
				auto dur = end - start;
	                        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();

				if (_time_ms - ms > 0) {
					this_thread::sleep_for(chrono::milliseconds(_time_ms-ms));
				} else	{
					cerr << "periodic timer: time too low " << ms << " < " << _time_ms << endl;
					this_thread::sleep_for(chrono::milliseconds(_time_ms));
				}
			}
		}

	private:
		bool _stop;
		function<void(void*)> _func;
		void* _data;
		int _time_ms;
		thread _worker;
};

static void PThelper(PeriodicTimer* p) 
{ 
	p->loop();
}

#endif
