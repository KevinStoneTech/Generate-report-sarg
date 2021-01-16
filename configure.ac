dnl Process this file with autoconf or autoreconf to produce a configure script.
AC_INIT([sarg],[2.4.0])
AC_CONFIG_SRCDIR([log.c])
AC_CONFIG_AUX_DIR([cfgaux])
AC_CONFIG_MACRO_DIR([m4])

dnl We don't use automake but the following macro is required to
dnl install "install-sh" that is required by configure.
dnl I may be a bug in autoconf 2.69...
dnl But if it is enabled, the AM_GNU_GETTEXT produce a warning!
dnl The solution for now is to manually run automake -a before
dnl running the configure script
dnl AM_INIT_AUTOMAKE

AC_CANONICAL_HOST

AC_ARG_WITH(gcc,
AS_HELP_STRING([--without-gcc],[use CC to compile]))

test -n "$CC" && cc_specified=yes
case ${with_gcc} in
  yes ) CC=gcc ;;
dnl yes ) CC=g++ ;;
  no  ) CC=cc ;;
  *   ) AC_PROG_CC;;
dnl  *   ) AC_PROG_CXX ;;
esac

dnl The purpose of the following condition is unknown but it is obsolete as it is.
dnl The -Aa option produces an error claiming that some argument are missing.
dnl if test "${CC}" = "cc" ; then
dnl    CFLAGS="${CFLAGS} -g -O2 -Aa"
dnl fi

dnl C99 support is required to define LLONG_MAX (at least on CentOS 5.7)
AC_PROG_CC_C99

# Report more warnings to improve code quality.
CFLAGS="${CFLAGS} -Wall"

dnl Check for supported compiler options

AC_MSG_CHECKING([for extra warnings flag in $CC])
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} -Wextra -Wno-unused-parameter"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([])],[have_extra_warnings="yes"],[have_extra_warnings="no"])
AC_MSG_RESULT($have_extra_warnings)
AS_IF([test "$have_extra_warnings" = "no"],[CFLAGS="${saved_CFLAGS}"])

# Don't compare signs as it is a mess
CFLAGS="${CFLAGS} -Wno-sign-compare"

AC_MSG_CHECKING([for implicit-function-declaration error flag in $CC])
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} -Werror=implicit-function-declaration"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([])],[have_implicit_function_declaration="yes"],[have_implicit_function_declaration="no"])
AC_MSG_RESULT($have_implicit_function_declaration)
AS_IF([test "$have_implicit_function_declaration" = "no"],[CFLAGS="${saved_CFLAGS}"])

AC_MSG_CHECKING([for format error flag in $CC])
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} -Werror=format"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([])],[have_error_format="yes"],[have_error_format="no"])
AC_MSG_RESULT($have_error_format)
AS_IF([test "$have_error_format" = "no"],[CFLAGS="${saved_CFLAGS}"])

case "$host" in
   *-solaris*)
   LDFLAGS="${LDFLAGS} -lsocket -lnsl"
   CFLAGS="-DSOLARIS ${CFLAGS}"
   ;;
esac

#dnl Checks for programs.
#AC_PROG_CC

dnl Check for headers
AC_HEADER_DIRENT
AC_HEADER_STDC


AC_CHECK_HEADERS(stdio.h stdlib.h string.h strings.h sys/time.h time.h unistd.h sys/dirent.h \
		dirent.h sys/types.h sys/socket.h netdb.h arpa/inet.h netinet/in.h sys/stat.h \
		ctype.h errno.h sys/resource.h sys/wait.h stdarg.h inttypes.h limits.h locale.h \
		execinfo.h math.h libintl.h libgen.h stdbool.h getopt.h fcntl.h fnmatch.h \
		winsock.h)

AS_IF([test $ac_cv_header_getopt_h = "no"],[AC_MSG_ERROR("getopt.h is required to compile sarg")])

# Build with gd
AC_ARG_WITH([gd],
	AS_HELP_STRING([--with-gd],[Compile with support for the graphical gd library]),
	[],[with_gd=check])
AS_IF([test "x$with_gd" != "xno"],
[
	AC_CHECK_HEADERS(gd.h gdfontl.h gdfontt.h gdfonts.h gdfontmb.h gdfontg.h)
	AS_IF([test "x$ac_cv_header_gd_h" = "xyes"],
	[
		AC_CHECK_LIB(gd, gdImagePng,LIBS="-lgd ${LIBS}"; HAVE_GD_LIB="yes", HAVE_GD_LIB="")
		AS_IF([test "x$HAVE_GD_LIB" != "xyes"],
		[
			AC_MSG_ERROR([libgd is required to compile sarg with gd])
		])
	],[
		gd_status="not found"
	])
],[
	gd_status="disabled"
])

# Build with LDAP
AC_ARG_WITH([ldap],
	AS_HELP_STRING([--with-ldap],[Compile with LDAP support]),
	[],[with_ldap=check])
AS_IF([test "x$with_ldap" != "xno"],
[
	AC_CHECK_HEADERS([ldap_cdefs.h] [ldap_features.h] [ldap.h],,break)
	AS_IF([test "x$ac_cv_header_ldap_h" = "xyes"],
	[
		AC_CHECK_LIB(ldap, ldap_init,LIBS="-lldap ${LIBS}"; HAVE_LDAP="yes", HAVE_LDAP="")
	],[
		ldap_status="not found"
	])
],[
	ldap_status="disabled"
])

# Build with iconv
AC_ARG_WITH([iconv],
	AS_HELP_STRING([--with-iconv],[Compile with support for iconv]),
	[],[with_iconv=check])
AS_IF([test "x$with_iconv" != "xno"],
[
	dnl Check for iconv
	AM_ICONV
	AS_IF([test -n "$LIBICONV"],[LIBS="$LIBS $LIBICONV"])
	AC_CHECK_HEADERS(iconv.h)
],[
	AC_MSG_NOTICE([Not building with iconv as requested on the configuration command line])
])

# Build with pcre
AC_ARG_WITH([pcre],
	AS_HELP_STRING([--with-pcre],[Compile with support for the Perl Compatible Regular Expressions library]),
	[],[with_pcre=check])
AS_IF([test "x$with_pcre" != "xno"],
[
	AC_CHECK_HEADERS(pcre.h)
	AS_IF([test "x$ac_cv_header_pcre_h" = "xyes"],
	[
		LIBS="$LIBS $(pcre-config --libs)"
		CFLAGS="$CFLAGS $(pcre-config --cflags)"
	],[
		pcre_status="not found"
	])
],[
	pcre_status="disabled"
])

# Build with file globbing
AC_ARG_WITH([glob],
	AS_HELP_STRING([--without-glob],[Ignore wildcards in file names]),
	[],[with_glob=yes])
AS_IF([test "x$with_glob" != "xno"],
[
	AC_CHECK_HEADERS([glob.h],[],
	[
		AS_IF([test "x$with_glob" != "xcheck"],
		[
			AC_MSG_FAILURE([glob.h not found (use --without-glob to compile without file globbing)])
		])
	])
],[
	glob_status="disabled"
])

# Build with zlib
AC_ARG_WITH([zlib],
	AS_HELP_STRING([--with-zlib],[Compile with support to decompress gz files]),
	[],[with_zlib=check])
AS_IF([test "x$with_zlib" != "xno" ],
[
	AC_CHECK_HEADERS(zlib.h)
	AS_IF([test "x$ac_cv_header_zlib_h" = "xyes"],
	[
		AC_CHECK_LIB([z],[gzopen],
		[
			LIBS="-lz ${LIBS}"
			HAVE_ZLIB_LIB="yes"
		],[
			HAVE_ZLIB_LIB=""
		])
		AS_IF([test "x$HAVE_ZLIB_LIB" != "xyes"],[AC_MSG_ERROR([zlib was not found])])
	],[
		zlib_status="not found"
	])
],[
	zlib_status="disabled"
])

# Build with bzlib
AC_ARG_WITH([bzlib],
	AS_HELP_STRING([--with-bzlib],[Compile with support to decompress bz2 files]),
	[],[with_bzlib=check])
AS_IF([test "x$with_bzlib" != "xno" ],
[
	AC_CHECK_HEADERS(bzlib.h)
	AS_IF([test "x$ac_cv_header_bzlib_h" = "xyes"],
	[
		AC_CHECK_LIB([bz2],[BZ2_bzReadOpen],
		[
			LIBS="-lbz2 ${LIBS}"
			HAVE_BZLIB_LIB="yes"
		],[
			HAVE_BZLIB_LIB=""
		])
		AS_IF([test "x$HAVE_BZLIB_LIB" != "xyes"],[AC_MSG_ERROR([bzlib was not found])])
	],[
		bzlib_status="not found"
	])
],[
	bzlib_status="disabled"
])

# Build with liblzma
AC_ARG_WITH([liblzma],
	AS_HELP_STRING([--with-liblzma],[Compile with support to decompress xz files]),
	[],[with_liblzma=check])
AS_IF([test "x$with_liblzma" != "xno" ],
[
	AC_CHECK_HEADERS(lzma.h)
	AS_IF([test "x$ac_cv_header_lzma_h" = "xyes"],
	[
		AC_CHECK_LIB([lzma],[lzma_stream_decoder],
		[
			LIBS="-llzma ${LIBS}"
			HAVE_LIBLZMA_LIB="yes"
		],[
			HAVE_LIBLZMA_LIB=""
		])
		AS_IF([test "x$HAVE_LIBLZMA_LIB" != "xyes"],[AC_MSG_ERROR([liblzma was not found])])
	],[
		liblzma_status="not found"
	])
],[
	liblzma_status="disabled"
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM

# Change the gettext version according to the available version on your system.
# It should not be necessary to change it unless you run autoreconf -fi.
AM_GNU_GETTEXT_VERSION([0.18])
AM_GNU_GETTEXT([external])

AC_SYS_LARGEFILE

# Check whether fopen64 is available and whether _LARGEFILE64_SOURCE
# needs to be defined for it
AC_MSG_CHECKING([for fopen64])
AC_CACHE_VAL(bu_cv_have_fopen64,
[noerror_CFLAGS=$CFLAGS
 CFLAGS="$CFLAGS -Werror"
 AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[FILE *f = fopen64 ("/tmp/foo","r");fclose(f);]])],[bu_cv_have_fopen64=yes],
 [CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE"
 AC_TRY_LINK([#include <stdio.h>], [FILE *f = fopen64 ("/tmp/foo","r");fclose(f);],
bu_cv_have_fopen64="need -D_LARGEFILE64_SOURCE",
 CFLAGS=$noerror_CFLAGS
 AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[FILE *f = fopen64 ("/tmp/foo","r");fclose(f);]])],[bu_cv_have_fopen64="yes without -Werror"
 werror_status="fail"],
 [CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE"
 AC_TRY_LINK([#include <stdio.h>], [FILE *f = fopen64 ("/tmp/foo","r");fclose(f);],
bu_cv_have_fopen64="need -D_LARGEFILE64_SOURCE and no -Werror"
werror_status="fail",
bu_cv_have_fopen64=no)]))
 ])
 CFLAGS=$noerror_CFLAGS])
AC_MSG_RESULT($bu_cv_have_fopen64)
AS_IF([test "$bu_cv_have_fopen64" != no],
[
	AC_DEFINE([HAVE_FOPEN64],1,[Is fopen64 available?])
	AS_IF([test "$bu_cv_have_fopen64" = "need -D_LARGEFILE64_SOURCE"],
	[
		AC_DEFINE([_LARGEFILE64_SOURCE],1,[Enable LFS])
	])
])

dnl check for functions
AC_CHECK_FUNCS(backtrace)
AC_CHECK_FUNCS(symlink)
AC_CHECK_FUNCS(lstat)
AC_CHECK_FUNCS(getnameinfo)
AC_CHECK_FUNCS(getaddrinfo)
AC_CHECK_FUNCS(mkstemp)
AC_CHECK_FUNCS(fnmatch)

dnl check for structure members
AC_CHECK_MEMBER([struct sockaddr_storage.ss_len],[AC_DEFINE([HAVE_SOCKADDR_SA_LEN],1,[ss_len in sockaddr_storage])])

dnl windows require this library
AS_IF([test $ac_cv_header_winsock_h = "yes"],
[
#   AC_CHECK_LIBS([ws2_32],[WSAGetLastError]) fails because of the __stdcall in the function prototype
	LIBS="$LIBS -lws2_32"
])

dnl check for the rlim_t size
AC_CHECK_SIZEOF(rlim_t,1,[#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
])
AS_IF([test $ac_cv_sizeof_rlim_t = "4"],
[
	AC_DEFINE(RLIM_STRING, "%d", [Rlim string])
],[test $ac_cv_sizeof_rlim_t = "8"],
[
	AC_DEFINE(RLIM_STRING, "%lli", [Rlim string])
],[
	AC_MSG_WARN([can not detect the size of your system rlim_t type])
])

dnl check for the long long int max constant
AC_CHECK_DECL(LLONG_MAX,HAVE_LLONG_MAX="yes",HAVE_LLONG_MAX="no",[[#include <limits.h>]])
AS_IF([test "x$ac_cv_have_decl_LLONG_MAX" != "xyes"],
[
	AC_MSG_ERROR([LLONG_MAX is not defined on your system.])
])

dnl Select sarg-php directory
AC_ARG_ENABLE(sargphp,
	AS_HELP_STRING([--enable-sargphp=sargphpdir],
	[Select sargphpdir as the directory to install sarg-php into]),
	[
		AS_IF([test "$enableval" -a "x$enableval" != "xno"],[SARGPHPDIR=$enableval])
	],[SARGPHPDIR="/var/www/html"])
AS_IF([test "$SARGPHPDIR"],
[
	AC_MSG_NOTICE([using $SARGPHPDIR as the directory to install sarg-php])
	AC_SUBST(SARGPHPDIR)
])

dnl Select fonts dir
AC_ARG_ENABLE(fontdir,
	AS_HELP_STRING([--enable-fontdir=fontdir],
	[Select fontdir as the directory with the fonts to use in the reports]),
	[
		AS_IF([test "$enableval" -a "x$enableval" != "xno"],[FONTDIR=$enableval])
	],[FONTDIR="${datarootdir}/sarg/fonts"])
AS_IF([test "$FONTDIR"],
[
	AS_IF([test "x$prefix" = "xNONE"],
	[
		tempfullpath=`prefix=$ac_default_prefix ; eval "echo $FONTDIR"`
	],[
		tempfullpath=`eval "echo $FONTDIR"`
	])
	AC_MSG_NOTICE([using $tempfullpath as the directory of the fonts])
	AC_SUBST(FONTDIR)
])

dnl Select images dir
AC_ARG_ENABLE(imagedir,
	AS_HELP_STRING([--enable-imagedir=imagedir],
	[Select imagedir as the directory with the images to use in the reports]),
	[
		AS_IF([test "$enableval"],[IMAGEDIR=$enableval])
	],[IMAGEDIR="${datarootdir}/sarg/images"])
AS_IF([test "x$prefix" = "xNONE"],
[
	tempfullpath=`prefix=$ac_default_prefix ; eval "echo $IMAGEDIR"`
],[
	tempfullpath=`eval "echo $IMAGEDIR"`
])
AC_MSG_NOTICE([using $tempfullpath as the directory of the images])
AC_SUBST(IMAGEDIR)

dnl Enable extra compile and run time protection
AC_ARG_ENABLE(extraprotection,
	AS_HELP_STRING([--enable-extraprotection],
	[Enable compile and runtime extra protections]),
[
	AS_IF([test "$enableval"],
	[
		# _FORTIFY_SOURCE may have been defined by the system. It must be undefined before it is changed to the value we want.
		CFLAGS="${CFLAGS} -fstack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
		AS_IF([test "x$werror_status" != "xfail"],[CFLAGS="${CFLAGS} -Werror"])

		AC_MSG_CHECKING([for format security flag in $CC])
		saved_CFLAGS="${CFLAGS}"
		CFLAGS="${CFLAGS} -Wformat -Werror=format-security"
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([])],[have_format_security="yes"],[have_format_security="no"])
		AC_MSG_RESULT($have_format_security)
		AS_IF([test "$have_format_security" = "no"],[CFLAGS="${saved_CFLAGS}"])

		AC_MSG_CHECKING([for empty body flag in $CC])
		saved_CFLAGS="${CFLAGS}"
		CFLAGS="${CFLAGS} -Wempty-body"
		AC_COMPILE_IFELSE([AC_LANG_SOURCE([])],[have_empty_body="yes"],[have_empty_body="no"])
		AC_MSG_RESULT($have_empty_body)
		AS_IF([test "$have_empty_body" = "no"],[CFLAGS="${saved_CFLAGS}"])
	])
])

dnl Enable double check of the data written in the reports
AC_ARG_ENABLE(doublecheck,
	AS_HELP_STRING([--enable-doublecheck],
	[Make sarg double check the data it manipulates and output a warning if an error is found]),
[
	AS_IF([test "$enableval"],
	[
		AC_DEFINE(ENABLE_DOUBLE_CHECK_DATA)
	])
])

dnl Get the xsl stylesheet to produce the manpage
AC_ARG_ENABLE(xsl-man,
	AS_HELP_STRING([--enable-xsl-man=man-xsl-style-sheet],
	[Select the directory containing the the XSL stylesheets to convert DocBook into man page]),
[
	AS_IF([test "$enableval"],
	[
		XSL_MAN_STYLESHEET=$enableval
		AC_SUBST(XSL_MAN_STYLESHEET)
	])
],
AC_CHECK_FILES([/usr/share/sgml/docbook/stylesheet/xsl/nwalsh/manpages/docbook.xsl],
[
	# debian
	XSL_MAN_STYLESHEET="/usr/share/sgml/docbook/stylesheet/xsl/nwalsh/manpages/docbook.xsl"
	AC_SUBST(XSL_MAN_STYLESHEET)
],[
	AC_CHECK_FILES([/usr/share/sgml/docbook/xsl-stylesheets/manpages/docbook.xsl],
	[
		# gentoo
		XSL_MAN_STYLESHEET="/usr/share/sgml/docbook/xsl-stylesheets/manpages/docbook.xsl"
		AC_SUBST(XSL_MAN_STYLESHEET)
	])
]))

dnl Get the xsl stylesheet to produce the html page
AC_ARG_ENABLE(xsl-html,
	AS_HELP_STRING([--enable-xsl-html=html-xsl-style-sheet],
	[Select the directory containing the the XSL stylesheets to convert DocBook into html page]),
[
	AS_IF([test "$enableval"],
	[
		XSL_HTML_STYLESHEET=$enableval
		AC_SUBST(XSL_HTML_STYLESHEET)
	])
],
AC_CHECK_FILES([/usr/share/sgml/docbook/stylesheet/xsl/docbook-xsl/html/onechunk.xsl],
[
	# debian
	XSL_HTML_STYLESHEET="/usr/share/sgml/docbook/stylesheet/xsl/docbook-xsl/html/onechunk.xsl"
	AC_SUBST(XSL_HTML_STYLESHEET)
],
[
AC_CHECK_FILES([/usr/share/sgml/docbook/xsl-stylesheets/html/onechunk.xsl],
[
	# gentoo
	XSL_HTML_STYLESHEET="/usr/share/sgml/docbook/xsl-stylesheets/html/onechunk.xsl"
	AC_SUBST(XSL_HTML_STYLESHEET)
])
]))

AC_SUBST(PACKAGE,"$PACKAGE_NAME")
AC_SUBST(VERSION,"$PACKAGE_VERSION")

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT

AS_IF([test "x$gd_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with gd as requested on the configuration command line])
],[test "x$gd_status" = "xnot found"],[
	AC_MSG_NOTICE([gd.h was not found so the graphs won't be available in the report])
])

AS_IF([test "x$pcre_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with pcre as requested on the configuration command line])
],[test "x$pcre_status" = "xnot found"],[
	AC_MSG_NOTICE([pcre.h was not found so the regexp won't be available in hostalias])
])

AS_IF([test "x$ldap_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with LDAP support as requested on the configuration command line])
],[test "x$ldap_status" = "xnot found"],[
	AC_MSG_NOTICE([ldap header files not found so LDAP is not available to resolve user's names])
])

AS_IF([test "x$glob_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with file globbing as requested on the configuration command line])
])

AS_IF([test "x$zlib_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with zlib as requested on the configuration command line])
],[test "x$zlib_status" = "xnot found"],[
	AC_MSG_NOTICE([zlib.h was not found so it won't be possible to process gzipped files])
])

AS_IF([test "x$bzlib_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with bzlib as requested on the configuration command line])
],[test "x$bzlib_status" = "xnot found"],[
	AC_MSG_NOTICE([bzlib.h was not found so it won't be possible to process bzipped files])
])

AS_IF([test "x$liblzma_status" = "xdisabled"],[
	AC_MSG_NOTICE([Not building with liblzma as requested on the configuration command line])
],[test "x$liblzma_status" = "xnot found"],[
	AC_MSG_NOTICE([lzma.h was not found so it won't be possible to process xz files])
])
