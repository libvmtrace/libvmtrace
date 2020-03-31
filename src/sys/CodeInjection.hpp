
#ifndef CODE_INJECTION_H
#define CODE_INJECTION_H

#include <algorithm>
#include <vector>
#include <memory>
#include <climits>
#include <libvmi/libvmi.h>

namespace libvmtrace
{
	inline static constexpr auto ALL_VCPU = ULONG_MAX;

	class SystemMonitor;

	class Patch
	{
		friend class InjectionStrategy;
		friend class PrimitiveInjectionStrategy;

	public:
		Patch(addr_t location, uint64_t pid, uint64_t vcpu, std::vector<uint8_t> data)
				: location(location), pid(pid), vcpu(vcpu), data(data) { }
	
	private:
		addr_t location;
		uint64_t pid;
		uint64_t vcpu;
		std::vector<uint8_t> data;
		std::vector<uint8_t> original;
		std::vector<std::shared_ptr<Patch>> dependencies;
	};

	class InjectionStrategy
	{
	public:
		InjectionStrategy(std::shared_ptr<SystemMonitor> sm) : sm(sm) { }

		virtual ~InjectionStrategy()
		{
			while (!patches.empty())
			{
				auto back = patches.back();
				patches.pop_back();
				Undo(back);
			}
		}
		
		virtual bool Apply(std::shared_ptr<Patch> patch)
		{
			// find patches that interleave with this one.
			for (auto& canidate : patches)	
				if (std::max(canidate->location, patch->location)
						<= std::min(canidate->location + canidate->data.size(),
							patch->location + patch->data.size()))
					patch->dependencies.push_back(canidate);
			
			patches.push_back(patch);	
			return true;
		}

		virtual bool Undo(std::shared_ptr<Patch> patch)
		{
			auto result = UndoPatch(patch);

			for (auto& dep : patch->dependencies)
				result |= UndoPatch(dep);

			return result;
		}

	protected:
		virtual bool UndoPatch(std::shared_ptr<Patch> patch)
		{
			patches.erase(std::remove(patches.begin(),
					patches.end(),
					patch));	
			return true;
		}
	
		std::vector<std::shared_ptr<Patch>> patches{};
		std::shared_ptr<SystemMonitor> sm;
	};
	
	class PrimitiveInjectionStrategy : public InjectionStrategy
	{
	public:
		PrimitiveInjectionStrategy(std::shared_ptr<SystemMonitor> sm);
		virtual bool Apply(std::shared_ptr<Patch> patch) override;
	private:
		virtual bool UndoPatch(std::shared_ptr<Patch> patch) override;
	};
}

#endif /* CODE_INJECTION_H */

