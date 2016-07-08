/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
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

#include <config.h>

#include "roken.h"

void ROKEN_LIB_FUNCTION
rk_cloexec(int fd)
{
#ifdef HAVE_FCNTL
    int ret;

    ret = fcntl(fd, F_GETFD);
    if (ret == -1)
	return;
    if (fcntl(fd, F_SETFD, ret | FD_CLOEXEC) == -1)
        return;
#endif
}

void ROKEN_LIB_FUNCTION
rk_cloexec_file(FILE *f)
{
#ifdef HAVE_FCNTL
    rk_cloexec(fileno(f));
#endif
}

void ROKEN_LIB_FUNCTION
rk_cloexec_dir(DIR * d)
{
#ifndef _WIN32
#ifdef HAVE_DIRFD
    rk_cloexec(dirfd(d));
#elif defined(__sun) && defined(__XOPEN_OR_POSIX)
    rk_cloexec(d->d_fd);
#elif defined(__sun) || defined(__hpux) || defined(_AIX)
    rk_cloexec(d->dd_fd);
#endif
#endif
}
