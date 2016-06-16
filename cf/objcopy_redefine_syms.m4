dnl @synopsis AC_PROG_OBJCOPY_REDFINE_SYMS
dnl See if we have objcopy and whether it has a working --redefine-syms option
dnl
dnl @author Dean Povey <dean.povey@quest.com>
dnl @category InstalledPackages
AC_DEFUN([AC_PROG_OBJCOPY_REDEFINE_SYMS],[dnl
# Check whether we have objcopy and it supports --redefine-syms
AC_CHECK_PROGS(OBJCOPY,objcopy,objcopy)
if test "x$OBJCOPY" != "x"; then
AC_CACHE_CHECK([whether objcopy supports --redefine_syms],
	    	   ac_cv_objcopy_has_redefine_syms,
[
# The following is overly familiar with autoconf internals
AC_TRY_COMPILE([#include <stdio.h>],
               [puts("hello world")],
[    # Rename symbol main -> old_main 
     rm -f conftest-cp.$ac_objext conftest.syms
     cat > conftest.syms <<_ACEOF
main old_main
_ACEOF
    $OBJCOPY --redefine-syms=conftest.syms conftest.$ac_objext conftest-cp.$ac_objext >&5 2>&1 
    OLD_LIBS=$LIBS
    LIBS="conftest-cp.$ac_objext"
    AC_TRY_LINK(,
        [int old_main( int argc, char **argv); old_main( 0, 0 );],
        ac_cv_objcopy_has_redefine_syms=yes,
        ac_cv_objcopy_has_redefine_syms=no)
    LIBS=$OLD_LIBS
    rm -f conftest.syms conftest-cp.$ac_objext 
],,ac_cv_objcopy_has_redefine_syms=no)
])
fi
test "x$ac_cv_objcopy_has_redefine_syms" = "xyes" && \
    objcopy_has_redefine_syms=yes
]) # AC_PROG_OBJCOPY_REDEFINE_SYMS
