
#include <stdint.h>

/* Simple implementation of CRC-32 */
namespace libvmtrace
{
namespace util
{
class Crc32
{
public:
	Crc32()
	{
		uint32_t polynomial = 0xEDB88320;

		for (uint32_t i = 0; i < 256; i++) 
		{
			uint32_t c = i;

			for (size_t j = 0; j < 8; j++) 
			{
				if (c & 1)
					c = polynomial ^ (c >> 1);
				else
					c >>= 1;
			}

			table[i] = c;
		}
	}

	uint32_t update(const void* buf, size_t len)
	{
		const uint8_t* u = static_cast<const uint8_t*>(buf);
		for (size_t i = 0; i < len; ++i)
			crc = table[(crc ^ u[i]) & 0xFF] ^ (crc >> 8); 
		
		crc ^= 0xFFFFFFFF;
		return crc;
	}

private:
	uint32_t table[256];
	uint32_t crc = 0xFFFFFFFF;
};
}
}

