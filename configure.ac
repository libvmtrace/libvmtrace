AC_PREREQ([2.69])
AC_INIT([libvmtrace], [0.1], [bt@sec.uni-passau.de,se@sec.uni-passau.de])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_CXXFLAGS="$AM_CXXFLAGS -std=c++17 -U__STRICT_ANSI__ -ggdb -Wall -Werror -pedantic"
CXXFLAGS="$CXXFLAGS -std=c++17 -U__STRICT_ANSI__ -Wall -Werror -pedantic"
CPPFLAGS="$CPPFLAGS -U__STRICT_ANSI__ -ggdb -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -I/usr/local/include"

AC_LANG([C++])
LT_INIT
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
#AC_PROG_RANLIB

AX_CXX_COMPILE_STDCXX_11

PKG_CHECK_MODULES([DEPS], [glib-2.0 >= 2.24.1])

AC_CHECK_LIB([pthread], [pthread_create])


AC_CHECK_HEADERS([boost/algorithm/string.hpp], [],
	[AC_MSG_ERROR(["Error! You need to have boost headers around."])]
)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa memset socket sqrt strerror strtoul])

AC_CONFIG_FILES([Makefile
                src/Makefile
                tests/Makefile
                apps/Makefile
                ])

AC_CHECK_LIB([pcap],[pcap_create])

AC_CHECK_LIB([vmi], [vmi_init])
  AC_CHECK_HEADERS([libvmi/libvmi.h], [],
   [AC_MSG_ERROR(["Error! You need to have libvmi headers around."])])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
	[Enable strict compiler checks @<:@no@:>@])],
	[debug="$enableval"],
	[debug="no"])
AM_CONDITIONAL([VMTRACE_DEBUG], [test x$debug = xyes])

AC_OUTPUT

AC_MSG_RESULT([
-------------------------------------------------------------------------------
Enable debug : $debug
-------------------------------------------------------------------------------
])
