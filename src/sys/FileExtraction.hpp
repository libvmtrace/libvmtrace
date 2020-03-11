
#pragma once

#include <cstdint>
#include <chrono>

namespace libvmtrace
{
namespace file_extraction
{
	constexpr auto magic_value = 0xAF0BF38u;
	constexpr auto default_size = 0x200;
	constexpr auto sleep_interval = std::chrono::milliseconds(1);

	template <typename T>
	constexpr auto to_underlying(T t) noexcept
	{
		return static_cast<std::underlying_type_t<T>>(t);
	}

	enum class status : uint8_t
	{
		endian_match = (1 << 0),
		transmitting_file_tree = (1 << 1),
		file_selected = (1 << 2),
		ready_signal = (1 << 3),
		error_abort = (1 << 4),
		skip_tree = (1 << 5)
	};

	// actual piece of memory mapped to the server, used for data transmission.
	struct shared_memory
	{
		uint32_t magic = magic_value;
		uint8_t status{};
		uint32_t buffer_size{};
		uint64_t transmission_size{};	
		uintptr_t buffer{};
		uint32_t crc{};
	};
	
	// helper class to manage status codes.
	class status_guard
	{
	public:
		status_guard(shared_memory& mem, status s) : mem(mem), s(s)
		{
			mem.status |= to_underlying(s);
		}

		~status_guard()
		{
			mem.status &= ~to_underlying(s);
		}
	
		status_guard(status_guard const& other) = delete;
		status_guard& operator=(status_guard const& other) = delete;
		status_guard(status_guard&& other) = delete;
		status_guard& operator=(status_guard&& other) = delete;	
	
	private:
		shared_memory& mem;
		status s;
	};
}
}

