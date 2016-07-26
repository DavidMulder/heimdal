/*
 * Copyright (c) 1997 - 2003 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

#ifdef HEIM_KRB5_DES

static OM_uint32
verify_mic_des
           (OM_uint32 * minor_status,
            const gsskrb5_ctx context_handle,
	    krb5_context context,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state,
	    krb5_keyblock *key,
	    const char *type
	    )
{
  u_char *p;
  CCDigestRef md5;
  u_char hash[16], *seq;
  DES_key_schedule schedule;
  EVP_CIPHER_CTX des_ctx;
  DES_cblock zero;
  DES_cblock deskey;
  uint32_t seq_number;
  OM_uint32 ret;
  int cmp;

  p = token_buffer->value;
  ret = _gsskrb5_verify_header (&p,
				   token_buffer->length,
				   type,
				   GSS_KRB5_MECHANISM);
  if (ret)
      return ret;

  if (memcmp(p, "\x00\x00", 2) != 0)
      return GSS_S_BAD_SIG;
  p += 2;
  if (memcmp (p, "\xff\xff\xff\xff", 4) != 0)
    return GSS_S_BAD_MIC;
  p += 4;
  p += 16;

  /* verify checksum */
  md5 = CCDigestCreate(kCCDigestMD5);
  CCDigestUpdate(md5, p - 24, 8);
  CCDigestUpdate(md5, message_buffer->value, message_buffer->length);
  CCDigestFinal(md5, hash);
  CCDigestDestroy(md5);

  memset (&zero, 0, sizeof(zero));
  memcpy (&deskey, key->keyvalue.data, sizeof(deskey));

#ifndef __APPLE_PRIVATE__
  DES_set_key_unchecked (&deskey, &schedule);
  DES_cbc_cksum ((void *)hash, (void *)hash, sizeof(hash),
		 &schedule, &zero);
#else
  CCDesCBCCksum(hash, hash, sizeof(hash), deskey, sizeof(deskey), &zero);
#endif
  if (ct_memcmp (p - 8, hash, 8) != 0) {
    memset (deskey, 0, sizeof(deskey));
    memset (&schedule, 0, sizeof(schedule));
    return GSS_S_BAD_MIC;
  }

  /* verify sequence number */

  HEIMDAL_MUTEX_lock(&context_handle->ctx_id_mutex);

  p -= 16;

  EVP_CIPHER_CTX_init(&des_ctx);
  EVP_CipherInit_ex(&des_ctx, EVP_des_cbc(), NULL, key->keyvalue.data, hash, 0);
  EVP_Cipher(&des_ctx, p, p, 8);
  EVP_CIPHER_CTX_cleanup(&des_ctx);

  memset (deskey, 0, sizeof(deskey));
  memset (&schedule, 0, sizeof(schedule));

  seq = p;
  _gss_mg_decode_le_uint32(seq, &seq_number);

  if (context_handle->more_flags & LOCAL)
      cmp = ct_memcmp(&seq[4], "\xff\xff\xff\xff", 4);
  else
      cmp = ct_memcmp(&seq[4], "\x00\x00\x00\x00", 4);

  if (cmp != 0) {
    HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
    return GSS_S_BAD_MIC;
  }

  ret = _gssapi_msg_order_check(context_handle->gk5c.order, seq_number);
  if (ret) {
      HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
      return ret;
  }

  HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);

  return GSS_S_COMPLETE;
}
#endif

#ifdef HEIM_KRB5_DES3
static OM_uint32
verify_mic_des3
           (OM_uint32 * minor_status,
            const gsskrb5_ctx context_handle,
	    krb5_context context,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state,
	    krb5_keyblock *key,
	    const char *type
	    )
{
  u_char *p;
  u_char *seq;
  uint32_t seq_number;
  OM_uint32 ret;
  krb5_crypto crypto;
  krb5_data seq_data;
  int cmp, docompat;
  Checksum csum;
  char *tmp;
  char ivec[8];

  p = token_buffer->value;
  ret = _gsskrb5_verify_header (&p,
				   token_buffer->length,
				   type,
				   GSS_KRB5_MECHANISM);
  if (ret)
      return ret;

  if (memcmp(p, "\x04\x00", 2) != 0) /* SGN_ALG = HMAC SHA1 DES3-KD */
      return GSS_S_BAD_SIG;
  p += 2;
  if (memcmp (p, "\xff\xff\xff\xff", 4) != 0)
    return GSS_S_BAD_MIC;
  p += 4;

  ret = krb5_crypto_init(context, key,
			 ETYPE_DES3_CBC_NONE, &crypto);
  if (ret){
      *minor_status = ret;
      return GSS_S_FAILURE;
  }

  /* verify sequence number */
  docompat = 0;
retry:
  if (docompat)
      memset(ivec, 0, 8);
  else
      memcpy(ivec, p + 8, 8);

  ret = krb5_decrypt_ivec (context,
			   crypto,
			   KRB5_KU_USAGE_SEQ,
			   p, 8, &seq_data, ivec);
  if (ret) {
      if (docompat++) {
	  krb5_crypto_destroy (context, crypto);
	  *minor_status = ret;
	  return GSS_S_FAILURE;
      } else
	  goto retry;
  }

  if (seq_data.length != 8) {
      krb5_data_free (&seq_data);
      if (docompat++) {
	  krb5_crypto_destroy (context, crypto);
	  return GSS_S_BAD_MIC;
      } else
	  goto retry;
  }

  HEIMDAL_MUTEX_lock(&context_handle->ctx_id_mutex);

  seq = seq_data.data;
  _gss_mg_decode_le_uint32(seq, &seq_number);

  if (context_handle->more_flags & LOCAL)
      cmp = ct_memcmp(&seq[4], "\xff\xff\xff\xff", 4);
  else
      cmp = ct_memcmp(&seq[4], "\x00\x00\x00\x00", 4);

  krb5_data_free (&seq_data);
  if (cmp != 0) {
      krb5_crypto_destroy (context, crypto);
      *minor_status = 0;
      HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
      return GSS_S_BAD_MIC;
  }

  ret = _gssapi_msg_order_check(context_handle->gk5c.order, seq_number);
  if (ret) {
      krb5_crypto_destroy (context, crypto);
      *minor_status = 0;
      HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
      return ret;
  }

  /* verify checksum */

  tmp = malloc (message_buffer->length + 8);
  if (tmp == NULL) {
      krb5_crypto_destroy (context, crypto);
      HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
      *minor_status = ENOMEM;
      return GSS_S_FAILURE;
  }

  memcpy (tmp, p - 8, 8);
  memcpy (tmp + 8, message_buffer->value, message_buffer->length);

  krb5_crypto_destroy (context, crypto);
  ret = krb5_crypto_init(context, key,
		       ETYPE_DES3_CBC_SHA1, &crypto);
  if (ret) {
    free(tmp);
    *minor_status = ret;
    HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
    return GSS_S_BAD_MIC;
  }

  csum.cksumtype = CKSUMTYPE_HMAC_SHA1_DES3;
  csum.checksum.length = 20;
  csum.checksum.data   = p + 8;

  ret = krb5_verify_checksum (context, crypto,
			      KRB5_KU_USAGE_SIGN,
			      tmp, message_buffer->length + 8,
			      &csum);
  free (tmp);
  if (ret) {
      krb5_crypto_destroy (context, crypto);
      *minor_status = ret;
      HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);
      return GSS_S_BAD_MIC;
  }
  HEIMDAL_MUTEX_unlock(&context_handle->ctx_id_mutex);

  krb5_crypto_destroy (context, crypto);
  return GSS_S_COMPLETE;
}
#endif

OM_uint32
_gsskrb5_verify_mic_internal
           (OM_uint32 * minor_status,
            const gsskrb5_ctx ctx,
	    krb5_context context,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state,
	    const char * type
	    )
{
    krb5_keyblock *key;
    OM_uint32 ret;

    if (ctx->more_flags & IS_CFX)
        return _gssapi_verify_mic_cfx (minor_status, &ctx->gk5c,
				       context, message_buffer, token_buffer,
				       qop_state);

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);
    ret = _gsskrb5i_get_token_key(ctx, context, &key);
    HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    *minor_status = 0;

    switch (key->keytype) {
#ifdef HEIM_KRB5_DES
    case KRB5_ENCTYPE_DES_CBC_CRC :
    case KRB5_ENCTYPE_DES_CBC_MD4 :
    case KRB5_ENCTYPE_DES_CBC_MD5 :
	ret = verify_mic_des (minor_status, ctx, context,
			      message_buffer, token_buffer, qop_state, key,
			      type);
	break;
#endif

#ifdef HEIM_KRB5_DES3
    case KRB5_ENCTYPE_DES3_CBC_MD5 :
    case KRB5_ENCTYPE_DES3_CBC_SHA1 :
	ret = verify_mic_des3 (minor_status, ctx, context,
			       message_buffer, token_buffer, qop_state, key,
			       type);
	break;
#endif

#ifdef HEIM_KRB5_ARCFOUR
    case KRB5_ENCTYPE_ARCFOUR_HMAC_MD5:
    case KRB5_ENCTYPE_ARCFOUR_HMAC_MD5_56:
	ret = _gssapi_verify_mic_arcfour (minor_status, ctx,
					  context,
					  message_buffer, token_buffer,
					  qop_state, key, type);
	break;
#endif

    default :
	ret = GSS_S_FAILURE;
	break;
    }
    krb5_free_keyblock (context, key);

    return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_verify_mic
           (OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            const gss_buffer_t message_buffer,
            const gss_buffer_t token_buffer,
            gss_qop_t * qop_state
	    )
{
    krb5_context context;
    OM_uint32 ret;

    GSSAPI_KRB5_INIT (&context);

    if (qop_state != NULL)
	*qop_state = GSS_C_QOP_DEFAULT;

    ret = _gsskrb5_verify_mic_internal(minor_status,
				       (gsskrb5_ctx)context_handle,
				       context,
				       message_buffer, token_buffer,
				       qop_state, (void *)(intptr_t)"\x01\x01");

    return ret;
}
