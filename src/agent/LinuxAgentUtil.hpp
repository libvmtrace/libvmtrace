
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <cassert>
#include <stdexcept>

namespace linux_agent
{
	// helper class to wrap the lifecycle of a shared memory object.
	class temporary_file
	{
	public:
		temporary_file(const std::string& name) : name(name)
		{
			assert(name.length() <= NAME_MAX);
			const auto descriptor = shm_open(name.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);

			if (descriptor == -1)
				throw std::runtime_error("Could not aquire file descriptor to temporary file."); 
			
			// close the descriptor to the temporary file, ifstream will aquire it's own descriptor.
			close(descriptor);
		}

		~temporary_file() noexcept(false)
		{
			if (shm_unlink(name.c_str()) == -1)
				throw std::runtime_error("Could not unlink temporary file from file system.");	
		}

		std::string get_mapped_name() const
		{
			return "/dev/shm" + name;
		}

		temporary_file(temporary_file const& other) = delete;
		temporary_file& operator=(temporary_file const& other) = delete;
		temporary_file(temporary_file&& other) = delete;
		temporary_file& operator=(temporary_file&& other) = delete;

	private:
		std::string name;
	};
}

