AM_CXXFLAGS = -pg -fpic  -O3 $(GLIB_CFLAGS) $(DEPS_CFLAGS)  -lpthread -I../rapidjson/include -I../spdlog/include -I ../libdwarfparser/ -I ../libdwarfparser/common/ -I ../apps/plugins/

AM_LDFLAGS = -L$(top_builddir)/src/.libs/

LDADD = -lm $(LIBS) $(GLIB_LIBS) $(DEPS_LDFLAGS) -lssl -lcrypto  -lboost_system -lboost_regex -lboost_filesystem -lboost_program_options
LDADD += -lvmtrace -lxentoollog -lxenctrl -lxenlight -ldwarf -lelf -lnetfilter_queue -lrdkafka++ -lcurl

bin_PROGRAMS = static_test_app static_test_injection_app static_test_elf_injection_app static_test_kafka_commander_app static_test_altp2m_app memory_test_app static_elasticsearch_test_app

static_test_app_SOURCES = static_test.cpp
static_test_injection_app_SOURCES = static_test_injection.cpp
static_test_kafka_commander_app_SOURCES = static_test_kafka_commander.cpp 
static_test_altp2m_app_SOURCES = static_test_altp2m.cpp
memory_test_app_SOURCES = memory_test.cpp
static_elasticsearch_test_app_SOURCES = static_elasticsearch_test.cpp
static_test_elf_injection_app_SOURCES = static_test_elf_injection.cpp

