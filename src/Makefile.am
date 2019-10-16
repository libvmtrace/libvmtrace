AM_CXXFLAGS = -pg -fpic -O0 $(GLIB_CFLAGS) $(DEPS_CFLAGS) -I ../rapidjson/include/ -I ../libdwarfparser/ -I ../libdwarfparser/common/

LDADD = -lxen 

libvmtrace_la_CPPFLAGS = -ggdb $(GLIB_CFLAGS) -lvmi -ldwarf

lib_LTLIBRARIES = libvmtrace.la

pkginclude_HEADERS = libvmtrace.hpp

if VMTRACE_DEBUG
libvmtrace_la_CPPFLAGS += -DVMTRACE_DEBUG
endif

libvmtrace_la_SOURCES = sys/SystemMonitor.cpp \
						sys/Int3.cpp \
						sys/Altp2mBasic.cpp \
						sys/Event.cpp \
						sys/Process.cpp \
						sys/ElfHelper.cpp \
						sys/OperatingSystem.cpp \
						sys/LinuxVM.cpp \
						sys/SyscallBasic.cpp \
						sys/SyscallJson.cpp \
						sys/RegisterMechanism.cpp \
						sys/Xen.cpp

libvmtrace_la_SOURCES += sys/DwarfHelper.cpp \
						../libdwarfparser/libdwarfparser/array.cpp \
						../libdwarfparser/libdwarfparser/basetype.cpp \
						../libdwarfparser/libdwarfparser/consttype.cpp \
						../libdwarfparser/libdwarfparser/dwarfexception.cpp \
						../libdwarfparser/libdwarfparser/dwarfparser.cpp \
						../libdwarfparser/libdwarfparser/enum.cpp \
						../libdwarfparser/libdwarfparser/funcpointer.cpp \
						../libdwarfparser/libdwarfparser/function.cpp \
						../libdwarfparser/libdwarfparser/instance.cpp \
						../libdwarfparser/libdwarfparser/pointer.cpp \
						../libdwarfparser/libdwarfparser/refbasetype.cpp \
						../libdwarfparser/libdwarfparser/referencingtype.cpp \
						../libdwarfparser/libdwarfparser/struct.cpp \
						../libdwarfparser/libdwarfparser/structured.cpp \
						../libdwarfparser/libdwarfparser/structuredmember.cpp \
						../libdwarfparser/libdwarfparser/symbol.cpp \
						../libdwarfparser/libdwarfparser/symbolmanager.cpp \
						../libdwarfparser/libdwarfparser/typedef.cpp \
						../libdwarfparser/libdwarfparser/union.cpp \
						../libdwarfparser/libdwarfparser/variable.cpp \
						../libdwarfparser/libvmiwrapper/libvmiwrapper.cpp \
						../libdwarfparser/libvmiwrapper/vmiinstance.cpp \
						../libdwarfparser/libvmiwrapper/vmiexception.cpp

libvmtrace_la_SOURCES += util/utils.cpp \
						 util/ProcessCache.cpp \
						 util/Logging.cpp \
						 util/KafkaLogger.cpp \
						 util/ElasticLogger.cpp \
						 util/Controller.cpp \
						 util/KafkaCommander.cpp

libvmtrace_la_SOURCES += net/IPv4Addr.cpp \
						 net/NetworkConnection.cpp \
						 net/IPv4Addr.hpp  \
						 net/Packet.cpp \
						 net/NetDev.cpp  \
						 net/NetFilter.hpp  \
						 net/NetProxy.hpp \
						 net/NetMonitor.cpp \
						 net/NetProxy.cpp
