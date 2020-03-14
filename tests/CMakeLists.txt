
cmake_minimum_required (VERSION 3.1)

project (vmtrace)

set (test_files
	static_test.cpp
	static_test_injection.cpp
	static_test_elf_injection.cpp
	static_test_kafka_commander.cpp
	static_test_altp2m.cpp
	static_elasticsearch_test.cpp
	memory_test.cpp)

set (test_libs
	ssl
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
	vmtrace
	xenctrl)

foreach (test_file ${test_files})
	string (REPLACE ".cpp" "" final_name ${test_file})
	add_executable (${final_name} ${test_file})
	add_dependencies (${final_name} vmtrace)
	target_include_directories (${final_name} PRIVATE .)
	target_link_libraries (${final_name} ${test_libs})
endforeach (test_file ${test_files})

