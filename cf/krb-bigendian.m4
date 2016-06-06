dnl
dnl $Id$
dnl

dnl check if this computer is little or big-endian
dnl if we can figure it out at compile-time then don't define the cpp symbol
dnl otherwise test for it and define it.  also allow options for overriding
dnl it when cross-compiling
dnl
dnl VAS Modifications by wynn.wilkes@quest.com
dnl  support for the __BIG|LITTLE_ENDIAN__ defines on OSX automatically
dnl  set by gcc depending on what architecture you are compiling for.


AC_DEFUN([KRB_C_BIGENDIAN], [
AC_ARG_ENABLE(bigendian,
	AC_HELP_STRING([--enable-bigendian],[the target is big endian]),
krb_cv_c_bigendian=yes)
AC_ARG_ENABLE(littleendian,
	AC_HELP_STRING([--enable-littleendian],[the target is little endian]),
krb_cv_c_bigendian=no)


AC_CACHE_CHECK(whether the compiler is setting __LITTLE|BIG_ENDIAN__,
krb_cv_c_bigendian_gcc,
[AC_TRY_COMPILE([],[
#if !defined(__BIG_ENDIAN__) && !defined(__LITTLE_ENDIAN__)
# error Not using gcc on OSX
#endif], krb_cv_c_bigendian_gcc=yes, krb_cv_c_bigendian_gcc=no)])


AC_CACHE_CHECK(whether byte order is known at compile time,
krb_cv_c_bigendian_compile,
[if test "$krb_cv_c_bigendian_gcc" = "no"; then
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/param.h>],[
#if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
 bogus endian macros
#endif], 
krb_cv_c_bigendian_compile=yes, krb_cv_c_bigendian_compile=no)
fi])
 
 
AC_CACHE_CHECK(whether byte ordering is bigendian, 
krb_cv_c_bigendian,
[if test "$krb_cv_c_bigendian_compile" = "yes"; then
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/param.h>],[
#if BYTE_ORDER != BIG_ENDIAN
  not big endian
#endif], krb_cv_c_bigendian=yes, krb_cv_c_bigendian=no)
  else
    AC_TRY_RUN([main () {
      /* Are we little or big endian?  From Harbison&Steele.  */
      union
      {
	long l;
	char c[sizeof (long)];
    } u;
    u.l = 1;
    exit (u.c[sizeof (long) - 1] == 1);
    }], krb_cv_c_bigendian=no, krb_cv_c_bigendian=yes,
    AC_MSG_ERROR([specify either --enable-bigendian or --enable-littleendian]))
  fi
])

if test "$krb_cv_c_bigendian_gcc" = "yes"; then
  AC_DEFINE(ENDIANESS_IN_GCC_DEFINES, 1, [define if gcc sets endianess flags])dnl
elif test "$krb_cv_c_bigendian" = "yes"; then
  AC_DEFINE(WORDS_BIGENDIAN, 1, [define if target is big endian])dnl
elif test "$krb_cv_c_bigendian_compile" = "yes"; then
  AC_DEFINE(ENDIANESS_IN_SYS_PARAM_H, 1, [define if sys/param.h defines the endiness])dnl
fi
AH_BOTTOM([
#if defined(ENDIANESS_IN_GCC_DEFINES)
# if defined(__BIG_ENDIAN__)
#  define WORDS_BIGENDIAN 1
# endif
#elif defined(ENDIANESS_IN_SYS_PARAM_H)
#  include <sys/types.h>
#  include <sys/param.h>
#  if BYTE_ORDER == BIG_ENDIAN
#  define WORDS_BIGENDIAN 1
#  endif
#endif
])
])
