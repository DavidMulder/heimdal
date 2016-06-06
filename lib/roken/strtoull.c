
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <roken.h>
#include <limits.h>

#ifndef HAVE_STRTOULL

#ifndef ULLONG_MAX

/* HPUX defines this here */
#ifdef ULONG_LONG_MAX
# define ULLONG_MAX ULONG_LONG_MAX
#else
#error NO ULONG LONG MAX VALUE AVAILABLE - FIX THIS FOR YOUR PLATFORM SPECIFIC DEFINE!!
#endif

#endif


unsigned long long int strtoull(const char* nptr, char** endptr, int base)
{
	const char *s;
	unsigned long long acc, cutoff, cutlim;
	unsigned int c;
	int neg, any;
	s = nptr;
	do
	{
		c = (unsigned char) *s++;
	} while(isspace(c));
	if(c == '-')
	{
		neg = 1;
		c = *s++;
	}
	else
	{
		neg = 0;
		if(c == '+')
			c = *s++;
	}
	if((base == 0 || base == 16)
		&& c == '0'
		&& (*s == 'x' || *s == 'X'))
	{
		c = s[1];
		s += 2;
		base = 16;
	}
	if(base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = ULLONG_MAX / (unsigned long long)base;
	cutlim = ULLONG_MAX % (unsigned long long)base;
	for(acc = 0, any = 0;; c = (unsigned char) *s++)
	{
		if(isdigit(c))
			c -= '0';
		else if(isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if(c >= (unsigned int)base)
			break;
		if(any < 0)
			continue;
		if(acc > cutoff || (acc == cutoff && c > cutlim))
		{
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		}
		else
		{
			any = 1;
			acc *= (unsigned long)base;
			acc += c;
		}
	}
	if(neg && any > 0)
		acc = -acc;
	if(endptr != 0)
		*endptr = (char *) (any ? s - 1 : nptr);
	return(acc);
}

#endif
