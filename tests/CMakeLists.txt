
cmake_minimum_required (VERSION 3.9)

project (vmtrace)

set (test_files
	static_test.cpp
	static_test_injection.cpp
	static_test_elf_injection.cpp
	static_test_elasticsearch.cpp
	static_test_agent_presence.cpp
	static_test_file_extraction.cpp
	static_test_primitive_injection.cpp
	static_test_extended_injection.cpp
	static_test_primitive_breakpoint.cpp
	static_test_extended_breakpoint.cpp
	memory_test.cpp
	memory_test_process.cpp)

foreach (test_file ${test_files})
	string (REPLACE ".cpp" "" final_name ${test_file})
	add_executable (${final_name} ${test_file})
	target_include_directories (${final_name} PRIVATE .)
	target_link_libraries (${final_name} vmtrace)
endforeach (test_file ${test_files})

