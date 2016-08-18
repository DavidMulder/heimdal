/*
 * Copyright (c) 1999 - 2001 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

static krb5_error_code
copy_hostname(krb5_context context,
	      const char *orig_hostname,
	      char **new_hostname)
{
    *new_hostname = strdup (orig_hostname);
    if (*new_hostname == NULL && context != NULL)
	return krb5_enomem(context);
    strlwr (*new_hostname);
    return 0;
}

/**
 * krb5_expand_hostname() tries to make orig_hostname into a more
 * canonical one in the newly allocated space returned in
 * new_hostname.

 * @param context a Keberos context
 * @param orig_hostname hostname to canonicalise.
 * @param new_hostname output hostname, caller must free hostname with
 *        krb5_xfree().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_expand_hostname (krb5_context context,
		      const char *orig_hostname,
		      char **new_hostname)
{
    struct addrinfo *ai = NULL, *a = NULL, hints;
    int error;
    int ret = 0;
    char localhost[MAXHOSTNAMELEN] = {0};
    size_t orig_len = 0;
    struct in_addr addr;
    struct hostent* hostinfo = NULL;

    memset( &addr, 0, sizeof(addr) );

    if (context && (context->flags & KRB5_CTX_F_DNS_CANONICALIZE_HOSTNAME) == 0)
	return copy_hostname (context, orig_hostname, new_hostname);

    memset (&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;

    /* Allow orig_hostname to be NULL so we can consolidate all hostname 
     * expansion logic in one place. We also process the 
     * computer_name_override setting in the conf file.
     * We then check the orig_hostname to see if it's already a FQDN.
     * Then we check the results of gethostbyname/gethostbyaddr to see if
     * there's an FQDN from there */
    if (orig_hostname == NULL) {
        const char* override = NULL;

        if (context) {
            override = krb5_config_get_string( context, NULL, "libdefaults",
                                               "computer_name_override", NULL );
        }

        if (override)
            strncpy( localhost, override, sizeof(localhost)-1 );
        else
            gethostname( localhost, sizeof(localhost) );

        orig_hostname = localhost;
    }
    
    if (strchr( orig_hostname, '.' ) && (orig_hostname[0] != '.') ) {
        if (inet_aton( orig_hostname, &addr ) == 0) {
            ret = copy_hostname( context, orig_hostname, new_hostname );
            goto FINISHED;
        } else {
            hints.ai_flags = AI_NUMERICHOST;
        }
    }

    if (hints.ai_flags == AI_CANONNAME ) {
        hostinfo = gethostbyname( orig_hostname );
    } else {
        hostinfo = gethostbyaddr( (char*) &addr, sizeof(addr), AF_INET );
    }

    if (hostinfo && hostinfo->h_name) {
        if (strchr( hostinfo->h_name, '.' ) && 
            (hostinfo->h_name[0] != '.') ) {
            ret = copy_hostname(context, hostinfo->h_name, new_hostname );
            goto FINISHED;
        } else {
            int     i;
            size_t  len = strlen( hostinfo->h_name );

            for( i = 0; hostinfo->h_aliases[i]; i++ ) {

                /* skip anything without a '.' in it, or that starts
                 * with a '.' */
                if( strchr( hostinfo->h_aliases[i], '.' ) == NULL ||
                    hostinfo->h_aliases[i][0] == '.' )
                    continue;

                /* if the FQDN alias does not start with the same thing
                 * as the hostname, it's probably some really weird
                 * situation, like having a line like:
                 * 127.0.0.1  rhas30 localhost.localdomain localhost
                 *
                 * in /etc/hosts. We don't want to use this hostname
                 * in this case, it needs to match 
                 * <orig_hostname>.fqdn.stuff.
                 **/
                if( strncmp( hostinfo->h_aliases[i],
                             hostinfo->h_name,
                             len ) ||
                    hostinfo->h_aliases[i][len] != '.' )
                    continue;

                ret = copy_hostname( context, 
                                     hostinfo->h_aliases[i], 
                                     new_hostname );
                goto FINISHED;
            }
        }
    }

    error = getaddrinfo (orig_hostname, NULL, &hints, &ai);
    /* Don't failover to orig_hostname here, and check for FQDN's */
    if( error == 0 ) {
    for (a = ai; a != NULL; a = a->ai_next) {
        /* only use FQDN's, so do the strchr search too */
        if( a->ai_canonname == NULL )
            continue;

        if( strchr( a->ai_canonname, '.' ) == NULL ||
            a->ai_canonname[0] == '.' )
            continue;

        ret = copy_hostname( context, a->ai_canonname, new_hostname );
        goto FINISHED;
    }
    }

    /* if we're not doing an IP address lookup, and
     * we haven't resolved anything, create a pseudo fqdn, otherwise
     * failover to the orig_hostname */
    if( context && (hints.ai_flags != AI_NUMERICHOST) ) {
        krb5_realm  realm = NULL;
        char*       pseudo_fqdn = NULL;

        if( krb5_get_default_realm( context, &realm ) == 0 ){
            if( asprintf( &pseudo_fqdn, "%s.%s", orig_hostname, realm ) < 0 ) {
                free( realm );
                goto FINISHED;
        }
            strlwr( pseudo_fqdn );
            ret = copy_hostname( context, pseudo_fqdn, new_hostname );
            free( pseudo_fqdn );
            free( realm );

            goto FINISHED;
	}
    }
    
    ret = copy_hostname (context, orig_hostname, new_hostname);

FINISHED:
    if( ai )
    freeaddrinfo (ai);
    return ret;
}

/*
 * handle the case of the hostname being unresolvable and thus identical
 */

static krb5_error_code
vanilla_hostname (krb5_context context,
		  const char *orig_hostname,
		  char **new_hostname,
		  char ***realms)
{
    krb5_error_code ret;

    ret = copy_hostname (context, orig_hostname, new_hostname);
    if (ret)
	return ret;
    strlwr (*new_hostname);

    ret = krb5_get_host_realm (context, *new_hostname, realms);
    if (ret) {
	free (*new_hostname);
	return ret;
    }
    return 0;
}

/**
 * krb5_expand_hostname_realms() expands orig_hostname to a name we
 * believe to be a hostname in newly allocated space in new_hostname
 * and return the realms new_hostname is believed to belong to in
 * realms.
 *
 * @param context a Keberos context
 * @param orig_hostname hostname to canonicalise.
 * @param new_hostname output hostname, caller must free hostname with
 *        krb5_xfree().
 * @param realms output possible realms, is an array that is terminated
 *        with NULL. Caller must free with krb5_free_host_realm().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_expand_hostname_realms (krb5_context context,
			     const char *orig_hostname,
			     char **new_hostname,
			     char ***realms)
{
    /* just use the other functions to figure this out */
    krb5_error_code ret = 0;

    ret = krb5_expand_hostname( context, orig_hostname, new_hostname );
    if( ret )
		return ret;

    return krb5_get_host_realm( context, *new_hostname, realms );
}
