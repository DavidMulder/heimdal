dnl Check for existance of sigsetjmp 
dnl
dnl AC_FUNC_SIGSETJMP()
AC_DEFUN([AC_FUNC_SIGSETJMP],
[AC_MSG_CHECKING(for sigsetjmp)
AC_TRY_COMPILE([#include <setjmp.h>],
    [sigjmp_buf bar; sigsetjmp(bar, 0);],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_SIGSETJMP,1,Whether we have a working sigsetjmp function)],
    [AC_MSG_RESULT(no)])
])
