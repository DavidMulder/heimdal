/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "der_locl.h"

#define ASN1_MAX_YEAR	2000

#ifndef HAVE_TIMEGM

static int
is_leap(unsigned y)
{
    y += 1900;
    return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

static const unsigned ndays[2][12] ={
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};

/*
 * This is a simplifed version of timegm(3) that doesn't accept out of
 * bound values that timegm(3) normally accepts but those are not
 * valid in asn1 encodings.
 */

/* Vintela modification: Changed the name back to _heim_timegm, just to be
 * more consistent with the _heim_gmtime function defined below which is NOT
 * part of the normal heimdal source!
 */

time_t
_heim_timegm (struct tm *tm)
{
  time_t res = 0;
  int i;

  /*
   * See comment in _der_gmtime
   */
  if (tm->tm_year > ASN1_MAX_YEAR)
      return 0;

  if (tm->tm_year < 0)
      return -1;
  if (tm->tm_mon < 0 || tm->tm_mon > 11)
      return -1;
  if (tm->tm_mday < 1 || tm->tm_mday > (int)ndays[is_leap(tm->tm_year)][tm->tm_mon])
      return -1;
  if (tm->tm_hour < 0 || tm->tm_hour > 23)
      return -1;
  if (tm->tm_min < 0 || tm->tm_min > 59)
      return -1;
  if (tm->tm_sec < 0 || tm->tm_sec > 59)
      return -1;

  for (i = 70; i < tm->tm_year; ++i)
    res += is_leap(i) ? 366 : 365;

  for (i = 0; i < tm->tm_mon; ++i)
    res += ndays[is_leap(tm->tm_year)][i];
  res += tm->tm_mday - 1;
  res *= 24;
  res += tm->tm_hour;
  res *= 60;
  res += tm->tm_min;
  res *= 60;
  res += tm->tm_sec;
  return res;
}

struct tm *
_der_gmtime(time_t t, struct tm *tm)
{
    time_t secday = t % (3600 * 24);
    time_t days = t / (3600 * 24);

    memset(tm, 0, sizeof(*tm));

    tm->tm_sec = secday % 60;
    tm->tm_min = (secday % 3600) / 60;
    tm->tm_hour = (int)(secday / 3600);

    /*
     * Refuse to calculate time ~ 2000 years into the future, this is
     * not possible for systems where time_t is a int32_t, however,
     * when time_t is a int64_t, that can happen, and this becomes a
     * denial of sevice.
     */
    if (days > (ASN1_MAX_YEAR * 365))
	return NULL;

    tm->tm_year = 70;
    while(1) {
	unsigned dayinyear = (is_leap(tm->tm_year) ? 366 : 365);
	if (days < dayinyear)
	    break;
	tm->tm_year += 1;
	days -= dayinyear;
    }
    tm->tm_mon = 0;

    while (1) {
	unsigned daysinmonth = ndays[is_leap(tm->tm_year)][tm->tm_mon];
	if (days < daysinmonth)
	    break;
	days -= daysinmonth;
	tm->tm_mon++;
    }
    tm->tm_mday = (int)(days + 1);

    return tm;
}

/* --- Begin Vintela Modification --- */

/* The following code fixes bug 12220 which may exist on platforms
 * where gmtime() accounts for leap seconds when timegm() doesn't.
 * When creating authenticators, a skew by leap seconds will cause mutual
 * authentication to fail. 
 *
 * So, the implemention of gmtime() below is meant to match the heimdal
 * implementation of timegm() above.  Neither account for leap seconds.
 *
 * If you ever find it necessary to change any of either of these functions
 * make sure that you run both of the tests below successfully.  The second
 * test (GMTIME_GMTIME) must be run on a system where the system gmtime isn't
 * accounting for leap seconds.
 *
 * -- matt.peterson@quest.com
 */
#define SECSPERDAY      86400
#define SECSPERHOUR	    3600
#define SECSPERMINUTE   60

struct tm* _heim_gmtime_r( const time_t *t, struct tm* tm )
{
  time_t days   = 0;
  time_t months = 0;
  time_t years  = 0;
  int    isleap = 0;
  time_t ngloc_t = 0;
  int days_in_year = 0;
  int days_in_month = 0;
 
  if( !t )
      return( NULL );
  else
      ngloc_t = *t;
 
  /* Zero out the tm structure */
  memset( tm, 0, sizeof(*tm) );

  /* seconds, minuts, hours */
  tm->tm_sec  = ngloc_t % SECSPERMINUTE;
  tm->tm_min  = (ngloc_t % SECSPERHOUR) / SECSPERMINUTE;
  tm->tm_hour = (ngloc_t % SECSPERDAY) / SECSPERHOUR;

  /* days */
  days = ngloc_t / SECSPERDAY;
  tm->tm_wday = ((4 + (days % 7)) % 7);

  /* years */
  years = 70; 

  if( is_leap(years) )
      days_in_year = 366;
  else
      days_in_year = 365;

  while( days >= days_in_year )
  {
     days -= days_in_year;
     years++;
     if( is_leap(years) )
         days_in_year = 366;
     else
         days_in_year = 365;
  }

  tm->tm_yday = days;
  tm->tm_year = years;
  isleap = is_leap( years );

  /* month and day of month */
  days_in_month = ndays[isleap][months]; 
  while( days >= days_in_month )
  {
     days -= ndays[isleap][months];
     months++;
     days_in_month = ndays[isleap][months]; 
  } 
  
  tm->tm_mon = months; 
  tm->tm_mday = days+1;
   
  return tm;
}

static struct tm _heim_tm;

struct tm* _heim_gmtime( const time_t *t )
{
    return _heim_gmtime_r( t, &_heim_tm );
}
/* The following function tests time value (every hour) for the entire 
 * (unsigned int) time_t range to ensure that _heim_timegm() and 
 * _heim_gmtime() are reciprocal.
 */
#ifdef TEST__HEIM_GMTIME_TIMEGM
int main( int argc, char* argv[])
{
   struct tm *tm;
   time_t t;
   time_t t1;

   for(t=0; t<2147483648L; t+=3599)
   { 
      tm = _heim_gmtime( &t );
      t1 = _heim_timegm( tm );
      if( t != t1 )
      {
         fprintf( stderr, "ERROR: t=%u, t1=%u\n", t, t1 );
         return 1;
      }
   }
   
   fprintf( stdout, "WOOT!\n");
      
   return 0;      
}
#endif

#ifdef TEST__HEIM_GMTIME_GMTIME
int main( int argc, char* argv[])
{
   struct tm *tm1;
   struct tm *tm2;
   time_t t;

   for(t=0; t<2147483648L; t+=3599)
   { 
      tm1 = _heim_gmtime( &t );
      tm2 = gmtime( &t );
      if( tm1->tm_sec != tm2->tm_sec || 
          tm1->tm_min != tm2->tm_min || 
          tm1->tm_hour != tm2->tm_hour || 
          tm1->tm_wday != tm2->tm_wday || 
          tm1->tm_mon != tm2->tm_mon || 
          tm1->tm_mday != tm2->tm_mday || 
          tm1->tm_year != tm2->tm_year || 
          tm1->tm_yday != tm2->tm_yday || 
          tm1->tm_isdst != tm2->tm_isdst ) 
      {
         fprintf( stderr, "ERROR: t=%u\n", t );
         fprintf( stderr, "tm1->tm_sec = %d\n", tm1->tm_sec ); 
         fprintf( stderr, "tm1->tm_min = %d\n", tm1->tm_min ); 
         fprintf( stderr, "tm1->tm_hour = %d\n", tm1->tm_hour ); 
         fprintf( stderr, "tm1->tm_wday = %d\n", tm1->tm_wday ); 
         fprintf( stderr, "tm1->tm_mon = %d\n", tm1->tm_mon ); 
         fprintf( stderr, "tm1->tm_mday = %d\n", tm1->tm_mday ); 
         fprintf( stderr, "tm1->tm_year = %d\n", tm1->tm_year ); 
         fprintf( stderr, "tm1->tm_yday = %d\n", tm1->tm_yday ); 
         fprintf( stderr, "tm1->tm_isdst = %d\n", tm1->tm_isdst ); 
         fprintf( stderr, "tm2->tm_sec = %d\n", tm2->tm_sec ); 
         fprintf( stderr, "tm2->tm_min = %d\n", tm2->tm_min ); 
         fprintf( stderr, "tm2->tm_hour = %d\n", tm2->tm_hour ); 
         fprintf( stderr, "tm2->tm_wday = %d\n", tm2->tm_wday ); 
         fprintf( stderr, "tm2->tm_mon = %d\n", tm2->tm_mon ); 
         fprintf( stderr, "tm2->tm_mday = %d\n", tm2->tm_mday ); 
         fprintf( stderr, "tm2->tm_year = %d\n", tm2->tm_year ); 
         fprintf( stderr, "tm2->tm_yday = %d\n", tm2->tm_yday ); 
         fprintf( stderr, "tm2->tm_isdst = %d\n", tm2->tm_isdst ); 
         return 1;
      }
   }
   fprintf( stdout, "WOOT!\n");
      
   return 0;      
}
#endif
/* --- End Vintela Modification --- */
#endif /* HAVE_TIMEGM */
