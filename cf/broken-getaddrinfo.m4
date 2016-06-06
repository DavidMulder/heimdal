dnl $Id$
dnl
dnl test if getaddrinfo can handle numeric services and AI_V4MAPPED

AC_DEFUN([rk_BROKEN_GETADDRINFO],[
AC_CACHE_CHECK([if getaddrinfo works], ac_cv_func_getaddrinfo_works,
AC_RUN_IFELSE([AC_LANG_SOURCE([[#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/utsname.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
# include <netinet/in6.h>
#endif

int
main(int argc, char **argv)
{
	const char *node = NULL;
	struct addrinfo hints, *ai;
	struct utsname utsname;

	uname(&utsname);
	if(strcmp(utsname.sysname,"HP-UX") == 0)
	{
		/* getaddrinfo is completely busted on HPUX 11i */
		return 1;
	}

		if(strcmp(utsname.sysname,"AIX") == 0 &&
			strcmp(utsname.version,"4") == 0)
	{
		/* getaddrinfo is completely busted on AIX 4.3.3 */
		return 1;
	}

	memset(&hints, 0, sizeof(hints));
	/* VAS Modification:
	  If you don't set the socktype, you should get addresses for all
	  supported socket types. On Solaris 10, you get nothing. So leave
	  the socktype empty and discover that bug. */
	/*hints.ai_socktype = SOCK_STREAM;*/
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = PF_UNSPEC;
	if(getaddrinfo(NULL, "17", &hints, &ai) != 0)
		return 1;
	if(getaddrinfo(NULL, "0", &hints, &ai) != 0)
		return 1;
	/* VAS Modification:
	1. Test whether getaddrinfo() actually accepts
	   the standard AI_* flags. Solaris 8 only accepts AI_PASSIVE,
	   AI_CANONNAME and AI_NUMERICHOST, despite other AI_* flags being
	   defined in <netdb.h>.
	2. OS X 10.6 does not support AI_V4MAPPED despite defining &
	   documenting it.
	3. Solaris 10 will not return addresses for a numeric service if
	   /etc/services does not contain an entry for that protocol.
	   Also, if you pass AI_NUMERICSERV but no socktype, it will return
	   nothing.
	   Also (not checked here), if you don't set AI_NUMERICSERV and you
	   don't set ai_socktype, it only returns SOCK_STREAM addresses
	   rather than all addresses (SOCK_STREAM, SOCK_DGRAM)
	   which is incorrect according to RFC 3493 page 25.
	*/
#ifdef HAVE_IPV6
	hints.ai_family = AF_INET6;
#endif
	hints.ai_flags = AI_V4MAPPED | AI_ALL | AI_NUMERICSERV;
	/* Try resolving IPv4 localhost to see if AI_V4MAPPED works. */
	node = "127.0.0.1";
	if(getaddrinfo(node, "17", &hints, &ai) != 0)
		return 1;
	/* End VAS Modification */
	return 0;
}
]])],[ac_cv_func_getaddrinfo_works=yes],[ac_cv_func_getaddrinfo_works=no]))])
dnl Heimdal's 1.5.3 version below, not sure why they added the extra
dnl ac_cv_func_getaddrinfo_numserv=yes
dnl ]])],[ac_cv_func_getaddrinfo_numserv=yes],[ac_cv_func_getaddrinfo_numserv=no],[ac_cv_func_getaddrinfo_numserv=yes]))])
