dnl Darwin does not provide the global variable environ when linking dynamicly.
dnl See http://lists.gnu.org/archive/html/bug-guile/2004-01/msg00013.html
dnl   for some discussion.


AC_DEFUN([rk_ENVIRON], [

    AC_CHECK_DECL( environ, 
    [ 
        dnl dummy line to avoid syntax errors
        /bin/true
    ],
    [
        dnl There's no declaration of environ- on darwin, see if we can use
        dnl _NSGetEnviron, otherwise roken will define an extern char** environ
        if test "x$ostype" = "xmacosx"; then
            AC_MSG_CHECKING([if _NSGetEnviron() can be used for environ])
            AC_TRY_LINK(
            [
                #include <sys/time.h>
                #include <crt_externs.h>
                #define environ (*_NSGetEnviron())
            ],
            [
                char** env= environ;
            ],
            [
                AC_MSG_RESULT(yes)
                AC_DEFINE( USE_NSGETENVIRON_FOR_ENVIRON, 1, 
                           [The _NSGetEnviron() function should be used to access the environ array] )
                LIBS="$LIBS -lSystem"
            ],
            [
                AC_MSG_RESULT(no)
                AC_MSG_ERROR([environ not available and _NSGetEnviron is not available])
            ])
        fi
    ])
])

