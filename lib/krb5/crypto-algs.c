/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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
#include "../asn1/cms_asn1.h"

#ifndef HEIMDAL_SMALLER
#define DES3_OLD_ENCTYPE 1
#endif

struct _krb5_checksum_type *_krb5_checksum_types[] = {
    &_krb5_checksum_none,
#ifdef HEIM_WEAK_CRYPTO
    &_krb5_checksum_crc32,
    &_krb5_checksum_rsa_md4,
    &_krb5_checksum_rsa_md4_des,
    &_krb5_checksum_rsa_md5_des,
#endif
#ifdef DES3_OLD_ENCTYPE
    &_krb5_checksum_rsa_md5_des3,
#endif
    &_krb5_checksum_rsa_md5,
    &_krb5_checksum_sha1,
    &_krb5_checksum_hmac_sha1_des3,
    &_krb5_checksum_hmac_sha1_aes128,
    &_krb5_checksum_hmac_sha1_aes256,
    &_krb5_checksum_hmac_md5
};

int _krb5_num_checksums
	= sizeof(_krb5_checksum_types) / sizeof(_krb5_checksum_types[0]);

/*
 * these should currently be in reverse preference order.
 * (only relevant for !F_PSEUDO) */

/* VAS Modification -- RC2 is needed for smart card */
struct _RC2_params {
    int maximum_effective_key;
};

static krb5_error_code
rc2_get_params(krb5_context context,
           const krb5_data *data,
           void **params,
           krb5_data *ivec)
{
    CMSRC2CBCParameter rc2params;
    struct _RC2_params *p;
    krb5_error_code ret;
    size_t size;

    ret = decode_CMSRC2CBCParameter(data->data, data->length, &rc2params, &size);
    if (ret) {
    krb5_set_error_message(context, ret, "Can't decode RC2 parameters");
    return ret;
    }
    p = malloc(sizeof(*p));
    if (p == NULL) {
    free_CMSRC2CBCParameter(&rc2params);
    krb5_set_error_message(context, ENOMEM, "malloc - out of memory");
    return ENOMEM;
    }
    /* XXX  */
    switch(rc2params.rc2ParameterVersion) {
    case 160:
    p->maximum_effective_key = 40;
    break;
    case 120:
    p->maximum_effective_key = 64;
    break;
    case 58:
    p->maximum_effective_key = 128;
    break;

    }
    if (ivec)
    ret = der_copy_octet_string(&rc2params.iv, ivec);
    free_CMSRC2CBCParameter(&rc2params);
    *params = p;

    return ret;
}

static krb5_error_code
rc2_set_params(krb5_context context,
           const void *params,
           const krb5_data *ivec,
           krb5_data *data)
{
    CMSRC2CBCParameter rc2params;
    const struct _RC2_params *p = params;
    int maximum_effective_key = 128;
    krb5_error_code ret;
    size_t size;

    memset(&rc2params, 0, sizeof(rc2params));

    if (p)
    maximum_effective_key = p->maximum_effective_key;

    /* XXX */
    switch(maximum_effective_key) {
    case 40:
    rc2params.rc2ParameterVersion = 160;
    break;
    case 64:
    rc2params.rc2ParameterVersion = 120;
    break;
    case 128:
    rc2params.rc2ParameterVersion = 58;
    break;
    }
    ret = der_copy_octet_string(ivec, &rc2params.iv);
    if (ret)
    return ret;

    ASN1_MALLOC_ENCODE(CMSRC2CBCParameter, data->data, data->length,
               &rc2params, &size, ret);
    if (ret == 0 && size != data->length)
    krb5_abortx(context, "Internal asn1 encoder failure");
    free_CMSRC2CBCParameter(&rc2params);

    return ret;
}

static void
rc2_schedule(krb5_context context,
         struct _krb5_key_type *kt,
         struct _krb5_key_data *kd,
         const void *params)
{
    const struct _RC2_params *p = params;
    int maximum_effective_key = 128;
    if (p)
    maximum_effective_key = p->maximum_effective_key;
    RC2_set_key (kd->schedule->data,
         kd->key->keyvalue.length,
         kd->key->keyvalue.data,
         maximum_effective_key);
}
/* End VAS Modification */

/* VAS Modification */
static krb5_error_code
RC2_CBC_encrypt(krb5_context context,
                struct _krb5_key_data *key,
                void *data,
                size_t len,
                krb5_boolean ngencrypt,
                int usage,
                void *ivec)
{
    unsigned char local_ivec[8];
    RC2_KEY *s = key->schedule->data;
    if(ivec == NULL) {
        ivec = &local_ivec;
        memset(local_ivec, 0, sizeof(local_ivec));
    }
    RC2_cbc_encrypt(data, data, len, s, ivec, ngencrypt);
    return 0;
}
/* End VAS Modification */

/* VAS Modification -- RC2 is needed for smart card */
static struct _krb5_key_type keytype_rc2 = {
    KEYTYPE_RC2,
    "rc2",
    128,
    16,
    1,
    sizeof(RC2_KEY),
    NULL,
    rc2_schedule,
    NULL, /* XXX salt */
    NULL,
    rc2_get_params,
    rc2_set_params,
    NULL,
    NULL
};
/* End VAS Modification */

/* VAS Modification -- RC2 is required by smart card */
static unsigned rc2CBC_num[] = { 1, 2, 840, 113549, 3, 2 };
static heim_oid rc2CBC_oid = kcrypto_oid_enc(rc2CBC_num);
static struct _krb5_encryption_type enctype_rc2_cbc_none = {
    ETYPE_RC2_CBC_NONE,
    "rc2-cbc-none",
    &rc2CBC_oid,
    NULL,
    8,
    8,
    0,
    &keytype_rc2,
    &_krb5_checksum_none,
    NULL,
    F_PSEUDO|F_PADCMS,
    RC2_CBC_encrypt,
    0,
    NULL
};
/* End VAS Modification */

struct _krb5_encryption_type *_krb5_etypes[] = {
    &_krb5_enctype_aes256_cts_hmac_sha1,
    &_krb5_enctype_aes128_cts_hmac_sha1,
    &_krb5_enctype_des3_cbc_sha1,
    &_krb5_enctype_des3_cbc_none, /* used by the gss-api mech */
    &_krb5_enctype_arcfour_hmac_md5,
#ifdef DES3_OLD_ENCTYPE
    &_krb5_enctype_des3_cbc_md5,
    &_krb5_enctype_old_des3_cbc_sha1,
#endif
#ifdef HEIM_WEAK_CRYPTO
    &_krb5_enctype_des_cbc_md5,
    &_krb5_enctype_des_cbc_md4,
    &_krb5_enctype_des_cbc_crc,
    &_krb5_enctype_des_cbc_none,
    &_krb5_enctype_des_cfb64_none,
    &_krb5_enctype_des_pcbc_none,
#endif
    &_krb5_enctype_null,
    &enctype_rc2_cbc_none /* VAS Modification -- added for smart card */
};

int _krb5_num_etypes = sizeof(_krb5_etypes) / sizeof(_krb5_etypes[0]);
