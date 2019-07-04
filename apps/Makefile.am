AM_CXXFLAGS = -pg -fpic  -O3 $(GLIB_CFLAGS) $(DEPS_CFLAGS)  -lpthread -I../rapidjson/include -I../spdlog/include -I ../libdwarfparser/ -I ../libdwarfparser/common/

AM_LDFLAGS = -L$(top_builddir)/src/.libs/

PLUGINS = plugins/SyscallLogger.cpp \
	  plugins/ProcessListLogger.cpp \
	  plugins/ProcessChangeLogger.cpp

LDADD = -lm $(LIBS) $(GLIB_LIBS) $(DEPS_LDFLAGS) -lssl -lcrypto  -lboost_system -lboost_regex -lboost_filesystem -lboost_program_options -lcurl
LDADD += -lvmtrace -lxentoollog -lxenctrl -lxenlight -ldwarf -lelf -lnetfilter_queue -lrdkafka++

bin_PROGRAMS = saracenia_app saracenia2_app dingfest_app code_section_integrity_app code_section_integrity_binary_app git_detect_app measurment_app measurment_pf_app ssh_key_extraction_app csec_app

saracenia_app_SOURCES = saracenia.cpp \
						ssh_helper/SSHHelper.cpp
saracenia_app_LDADD = $(LDADD) -lssh

saracenia2_app_SOURCES = saracenia2.cpp \
						 ssh_helper/SSHHelper.cpp
saracenia2_app_LDADD = $(LDADD) -lssh

dingfest_app_SOURCES = dingfest.cpp $(PLUGINS)

measurment_app_SOURCES = measurment.cpp $(PLUGINS)

measurment_pf_app_SOURCES = measurment_pf.cpp $(PLUGINS)

code_section_integrity_app_SOURCES = code_section_integrity.cpp
code_section_integrity_app_LDADD = $(LDADD)

code_section_integrity_binary_app_SOURCES = code_section_integrity_binary.cpp
code_section_integrity_binary_app_LDADD = $(LDADD)

git_detect_app_SOURCES = git_detect.cpp \
						 ssh_helper/SSHHelper.cpp
git_detect_app_LDADD = $(LDADD) -lssh

ssh_key_extraction_app_SOURCES = ssh_key_extraction.cpp \
								 ssh_helper/SSHHelper.cpp
ssh_key_extraction_app_LDADD = $(LDADD) -lssh

csec_app_SOURCES = csec.cpp $(PLUGINS)