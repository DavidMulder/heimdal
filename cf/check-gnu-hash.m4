dnl Detect whether gcc compiles binaries that use the GNU hash on
dnl this platform and turn it off.

AC_DEFUN([AC_DISABLE_GNU_HASH],[

AC_MSG_CHECKING([whether gcc uses --hash-style=gnu])
if test "x`${CC} -dumpspecs|grep hash-style=gnu`" != x
then
    AC_MSG_RESULT([yes. (changing to both)])
    # We need to add --hash-style=both to the linker flags. Otherwise
    # the binaries we build will not work on older runtime linkers. 
    DISABLE_GNU_HASH=1
    LDFLAGS="$LDFLAGS -Wl,--hash-style=both"
else
    AC_MSG_RESULT(no)
fi
])
