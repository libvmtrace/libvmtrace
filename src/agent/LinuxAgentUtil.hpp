
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <stdexcept>

namespace linux_agent
{
	// helper class to wrap the lifecycle of a shared memory object.
	class temporary_file
	{
	public:
		temporary_file(const std::string& name)
		{
			constexpr auto max_length = 249;

			if (name.size() > max_length)
				throw std::runtime_error("Temporary file name too large.");

			descriptor = memfd_create(name.c_str(), 0);

			if (descriptor == -1)
				throw std::runtime_error("Could not aquire file descriptor to temporary file."); 
		}

		~temporary_file()
		{
			close(descriptor);
		}

		int32_t get_descriptor() const
		{
			return descriptor;
		}

		temporary_file(temporary_file const& other) = delete;
		temporary_file& operator=(temporary_file const& other) = delete;
		temporary_file(temporary_file&& other) = delete;
		temporary_file& operator=(temporary_file&& other) = delete;

	private:
		int32_t descriptor;
	};
}

