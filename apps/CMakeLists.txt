
cmake_minimum_required (VERSION 3.1)

project (vmtrace)

set (apps_files
	code_section_integrity.cpp
	code_section_integrity_binary.cpp
	csec.cpp
	dingfest.cpp
	git_detect.cpp
	saracenia.cpp
	saracenia2.cpp
	ssh_key_extraction.cpp)

set (helper_files ssh_helper/SSHHelper.cpp)

set (plugin_files
	plugins/ProcessChangeLogger.cpp
	plugins/ProcessListLogger.cpp
	plugins/SyscallLogger.cpp)

foreach (apps_file ${apps_files})
	string (REPLACE ".cpp" "" final_name ${apps_file})
	add_executable (${final_name} ${apps_file} ${helper_files} ${plugin_files})
	target_include_directories (${final_name} PRIVATE .)
	target_link_libraries (${final_name} vmtrace)
endforeach (apps_file ${apps_files})

