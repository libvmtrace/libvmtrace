
cmake_minimum_required (VERSION 3.1)

project (vmtrace)

set (sys_files
	sys/SystemMonitor.cpp
	sys/Int3.cpp
	sys/Altp2mBasic.cpp
	sys/Event.cpp
	sys/Process.cpp
	sys/ElfHelper.cpp
	sys/OperatingSystem.cpp
	sys/LinuxVM.cpp
	sys/SyscallBasic.cpp
	sys/SyscallJson.cpp
	sys/RegisterMechanism.cpp
	sys/Xen.cpp
	sys/LinuxELFInjector.cpp
	sys/LinuxFileExtractor.cpp
	sys/DwarfHelper.cpp)

set (util_files
	util/utils.cpp
	util/ProcessCache.cpp
	util/Logging.cpp
	util/KafkaLogger.cpp
	util/ElasticLogger.cpp
	util/Controller.cpp
	util/KafkaCommander.cpp)

set (net_files
	net/IPv4Addr.cpp
	net/NetworkConnection.cpp
	net/IPv4Addr.hpp
	net/Packet.cpp
	net/NetDev.cpp
	net/NetMonitor.cpp
	net/NetProxy.cpp)

add_library (vmtrace ${sys_files} ${util_files} ${net_files})
add_dependencies (vmtrace libvmi librdkafka)
target_include_directories (vmtrace PUBLIC ${CMAKE_BINARY_DIR}/librdkafka-prefix/include)

add_executable (linux_file_extraction_agent agent/LinuxFileExtractionAgent.cpp)
target_link_libraries (linux_file_extraction_agent PRIVATE rt)

