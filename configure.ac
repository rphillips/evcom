#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([evcom], [dev], [])

AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

##########################################################################
# debug compilation support
##########################################################################

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    AM_CPPFLAGS="$AM_CPPFLAGS -g3 -ggdb -O0"
else
    AC_DEFINE([NDEBUG],[],[No debug])
    AM_CPPFLAGS="$AM_CPPFLAGS -O2"
fi

AC_SUBST([AM_CPPFLAGS])

##########################################################################
# libev compilation support
##########################################################################

EVPATH=
AC_ARG_WITH([ev],
            [AS_HELP_STRING([--with-ev=DIR],
                            [specify libev path])
            ],
            [EVPATH=$withval],
            [])

if test x$EVPATH != x ; then
    CFLAGS="$CFLAGS -I$EVPATH/include"
    CPPFLAGS="$CPPFLAGS -I$EVPATH/include"
    LDFLAGS="$LDFLAGS -L$EVPATH/lib"
    AC_CHECK_HEADERS(ev.h)
fi

AC_CHECK_LIB([ev],
             [ev_default_fork],
             [LIBS="$LIBS -lev"],
             AC_MSG_ERROR([Unable to find ev library]),
             [])

##########################################################################
# Checks for library functions.
##########################################################################
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CONFIG_FILES([Makefile
                 test/Makefile
                ])
AC_OUTPUT
