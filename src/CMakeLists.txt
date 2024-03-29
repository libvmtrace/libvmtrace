
cmake_minimum_required (VERSION 3.9)

project (vmtrace)

set (sys_files
	sys/SystemMonitor.cpp
	sys/BreakpointMechanism.cpp
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
	sys/DwarfHelper.cpp
	sys/PrimitiveInjectionStrategy.cpp
	sys/ExtendedInjectionStrategy.cpp)

set (util_files
	util/utils.cpp
	util/ProcessCache.cpp
	util/Logging.cpp
	util/ElasticLogger.cpp
	util/Controller.cpp)

set (net_files
	net/IPv4Addr.cpp
	net/NetworkConnection.cpp
	net/IPv4Addr.hpp
	net/Packet.cpp
	net/NetDev.cpp
	net/NetMonitor.cpp
	net/NetProxy.cpp)


set (agent linux_agent.o)
add_library (vmtrace ${sys_files} ${util_files} ${net_files} ${agent})
set_source_files_properties (${agent} PROPERTIES EXTERNAL_OBJECT true GENERATED true)

add_executable (linux_file_extraction_agent agent/LinuxFileExtractionAgent.cpp)
set_property (TARGET linux_file_extraction_agent PROPERTY LINK_LIBRARIES "")
target_link_libraries (linux_file_extraction_agent PRIVATE pthread rt -static)

add_custom_command(TARGET linux_file_extraction_agent
	POST_BUILD
	COMMENT "Performing objcopy of extraction agent to binary"
	COMMAND objcopy -B i386 -I binary -O elf64-x86-64 ../bin/linux_file_extraction_agent linux_agent.o
	VERBATIM)

add_dependencies (vmtrace linux_file_extraction_agent)
add_dependencies (linux_file_extraction_agent libvmi libdwarfparser)

install (TARGETS vmtrace DESTINATION lib)
install (DIRECTORY "${CMAKE_SOURCE_DIR}/src/" DESTINATION include/libvmtrace FILES_MATCHING PATTERN "*.hpp")

