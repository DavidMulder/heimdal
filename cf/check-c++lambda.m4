
# Check for C++ lambda support 
# AC_COMPILE_STDCXX_LAMBDA
AC_DEFUN([AC_COMPILE_STDCXX_LAMBDA], [
  AC_CACHE_CHECK(if compiler supports C++ lambda without additional flags,
  ac_cv_cxx_compile_cxxlambda_native,
  [AC_LANG_SAVE
  AC_LANG_CPLUSPLUS
  AC_TRY_COMPILE([
    #include <algorithm>
    #include <array>
    std::array< int, 2 > intarray;
    int x = 0;],
    [std::for_each( std::begin( intarray ), std::end( intarray ), [&]( const int i ) { x += i; } );],
  ac_cv_cxx_compile_cxxlambda_native=yes, ac_cv_cxx_compile_cxxlambda_native=no)
  AC_LANG_RESTORE
  ])

  AC_CACHE_CHECK(if compiler supports C++ lambda with -stdlib=libc++,
  ac_cv_cxx_compile_cxxlambda_stdlib,
  [AC_LANG_SAVE
  AC_LANG_CPLUSPLUS
  ac_save_CXXFLAGS="$CXXFLAGS"
  CXXFLAGS="$CXXFLAGS -stdlib=libc++"
  AC_TRY_COMPILE([
    #include <algorithm>
    #include <array>
    std::array< int, 2 > intarray;
    int x = 0;],
    [std::for_each( std::begin( intarray ), std::end( intarray ), [&]( const int i ) { x += i; } );],
  ac_cv_cxx_compile_cxxlambda_stdlib=yes, ac_cv_cxx_compile_cxxlambda_stdlib=no)
  CXXFLAGS="$ac_save_CXXFLAGS"
  AC_LANG_RESTORE
  ])

  if test "$ac_cv_cxx_compile_cxxlambda_native" = yes ||
     test "$ac_cv_cxx_compile_cxxlambda_stdlib" = yes; then
    AC_DEFINE(HAVE_STDCXX_LAMBDA,,[Define if compiler supports C++ lambda. ])
  else
    AC_MSG_ERROR([Your compiler doesn't support C++ lambda. Time to upgrade.])
  fi

  if test "$ac_cv_cxx_compile_cxxlambda_native" = no; then
    CXXFLAGS="$CXXFLAGS -stdlib=libc++"
  fi
])
