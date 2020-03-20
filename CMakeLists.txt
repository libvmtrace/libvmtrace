
cmake_minimum_required (VERSION 3.9)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -Ulinux")
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
project (vmtrace)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PKG_GLIB REQUIRED glib-2.0)

find_path (GLIB_INCLUDE_DIR NAMES glib.h PATH_SUFFIXES glib-2.0)
find_path (GLIB_CONF_INCLUDE_DIR NAMES glibconfig.h PATH_SUFFIXES glib-2.0/include PATHS ${PKG_GLIB_INCLUDE_DIRS} ${PKG_GLIB_LIBRARIES} ${CMAKE_SYSTEM_LIBRARY_PATH})

include_directories (${GLIB_INCLUDE_DIR}
	${GLIB_CONF_INCLUDE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/contrib/libvmi
	${CMAKE_CURRENT_SOURCE_DIR}/contrib/rapidjson/include
	${CMAKE_CURRENT_SOURCE_DIR}/contrib/drakvuf/src
	${CMAKE_CURRENT_SOURCE_DIR}/contrib/libdwarfparser
	${CMAKE_CURRENT_SOURCE_DIR}/contrib/libdwarfparser/libdwarfparser
	${CMAKE_CURRENT_SOURCE_DIR}/contrib/spdlog/include
	${CMAKE_CURRENT_SOURCE_DIR}/src
	${CMAKE_CURRENT_SOURCE_DIR}/apps/plugins)

# bring in all the dependencies
include (ExternalProject)
ExternalProject_Add(libvmi
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/contrib/libvmi
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>)
set (libdwarfparser_flags "-I${CMAKE_CURRENT_SOURCE_DIR}/contrib/libvmi -DLIBVMI_EXTRA_GLIB -DENABLE_KVM=OFF")
ExternalProject_Add(libdwarfparser
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/contrib/libdwarfparser
	CONFIGURE_COMMAND ./autogen.sh && ./configure LDFLAGS=-L${CMAKE_CURRENT_BINARY_DIR}/libvmi-prefix/lib CPPFLAGS=${libdwarfparser_flags} --prefix=<INSTALL_DIR>
	BUILD_IN_SOURCE 1)
ExternalProject_Add(librdkafka
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/contrib/librdkafka
	CONFIGURE_COMMAND ./configure --prefix=<INSTALL_DIR>
	BUILD_IN_SOURCE 1)

# dependencies between the dependencies...
add_dependencies (libdwarfparser libvmi)

# add the dependencies to the linker path
link_directories (${CMAKE_CURRENT_BINARY_DIR}/libdwarfparser-prefix/lib
	${CMAKE_CURRENT_BINARY_DIR}/librdkafka-prefix/lib
	${CMAKE_CURRENT_BINARY_DIR}/libvmi-prefix/lib)

link_libraries (ssl
	ssh
	crypto
	boost_system
	boost_regex
	boost_filesystem
	boost_program_options
	curl
	pthread
	pcap
	netfilter_queue
	elf
	rdkafka++
	dwarf
	dwarfparser
	vmiwrapper
	vmi
	xenctrl)

add_subdirectory (src)
add_subdirectory (tests)
add_subdirectory (apps)

