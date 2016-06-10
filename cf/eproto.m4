dnl
dnl Test to determine if EPROTONOSUPPORT is used instead of EPROTO. If
dnl so, then we define EPROTO to EPROTONOSUPPORT. This is the case on Darwin
dnl

AC_DEFUN([rk_EPROTO], [

    AC_MSG_CHECKING([for EPROTO])
    AC_TRY_COMPILE(
    [
        #include<sys/errno.h>
    ],
    [
        int foo= EPROTO;
    ],
    [
        AC_MSG_RESULT(yes)
    ],
    [
        AC_MSG_RESULT(no)
        AC_MSG_CHECKING([for EPROTONOSUPPORT])
        AC_TRY_COMPILE(
        [
            #include<sys/errno.h>
        ],
        [
            int foo= EPROTONOSUPPORT;
        ],
        [
            AC_MSG_RESULT(yes)
                AC_DEFINE(EPROTO, EPROTONOSUPPORT, 
                          [Define to EPROTONOSUPPORT if EPROTONOSUPPORT is available and EPROTO is not.])
        ],
        [
            AC_MSG_RESULT(no)
                AC_ERROR([ No definition for EPROTO or EPROTONOSUPPORT.])
        ])
    ])
])
