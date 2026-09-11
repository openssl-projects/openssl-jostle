//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <string.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "bc_err_codes.h"
#include "certpath.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

/*
 * Every certificate is decoded into an X509_new_ex object bound to the global
 * lib ctx. X509_verify resolves the signature algorithm through the
 * CERTIFICATE's lib ctx, not the store ctx's, so an unbound certificate would
 * verify in the default provider even under a fips=yes ctx — correct-looking
 * crypto from the wrong library, and invisible to any functional test.
 */
static X509 *decode_bound(const uint8_t *der, int32_t len)
{
    const unsigned char *p = der;
    X509 *cert = X509_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);

    if (cert == NULL)
    {
        return NULL;
    }
    if (d2i_X509(&cert, &p, (long) len) == NULL)
    {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

/*
 * Same binding rule as decode_bound: X509_CRL_verify resolves the signature
 * algorithm through the CRL's own lib ctx, so an unbound CRL would have its
 * signature checked in the default provider under a fips=yes ctx.
 */
static X509_CRL *decode_bound_crl(const uint8_t *der, int32_t len)
{
    const unsigned char *p = der;
    X509_CRL *crl = X509_CRL_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);

    if (crl == NULL)
    {
        return NULL;
    }
    if (d2i_X509_CRL(&crl, &p, (long) len) == NULL)
    {
        X509_CRL_free(crl);
        return NULL;
    }
    return crl;
}

static int32_t capture_chain(X509_STORE_CTX *ctx, certpath_result *result)
{
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int n;
    int i;
    size_t total = 0;

    if (chain == NULL)
    {
        return JO_SUCCESS;
    }
    n = sk_X509_num(chain);
    if (n <= 0)
    {
        return JO_SUCCESS;
    }

    result->chain_sizes = OPENSSL_malloc(sizeof(int32_t) * (size_t) n);
    if (result->chain_sizes == NULL)
    {
        return JO_FAIL;
    }

    for (i = 0; i < n; i++)
    {
        int len = i2d_X509(sk_X509_value(chain, i), NULL);
        if (len <= 0)
        {
            OPENSSL_free(result->chain_sizes);
            result->chain_sizes = NULL;
            return JO_FAIL;
        }
        result->chain_sizes[i] = (int32_t) len;
        total += (size_t) len;
    }

    result->chain_der = OPENSSL_malloc(total);
    if (result->chain_der == NULL)
    {
        OPENSSL_free(result->chain_sizes);
        result->chain_sizes = NULL;
        return JO_FAIL;
    }

    {
        unsigned char *w = result->chain_der;
        for (i = 0; i < n; i++)
        {
            if (i2d_X509(sk_X509_value(chain, i), &w) <= 0)
            {
                OPENSSL_free(result->chain_der);
                OPENSSL_free(result->chain_sizes);
                result->chain_der = NULL;
                result->chain_sizes = NULL;
                return JO_FAIL;
            }
        }
    }
    result->chain_len = total;
    result->chain_count = (int32_t) n;
    return JO_SUCCESS;
}

int32_t certpath_verify(const uint8_t *der, size_t der_len,
                        const int32_t *sizes, int32_t count, int32_t crl_count,
                        int32_t anchor_count,
                        int64_t time_secs, int32_t strict, int32_t revocation,
                        certpath_result *result)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    STACK_OF(X509) *untrusted = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509 *target = NULL;
    size_t off = 0;
    int32_t i;
    int32_t ret = JO_FAIL;

    /* Bridge-validated; asserted here as invariants per native-code.md. */
    jo_assert(der != NULL);
    jo_assert(sizes != NULL);
    jo_assert(result != NULL);
    jo_assert(count >= 2);
    jo_assert(crl_count >= 0);
    jo_assert(anchor_count >= 1 && anchor_count < count);

    memset(result, 0, sizeof(*result));
    result->depth = -1;

    store = X509_STORE_new();
    untrusted = sk_X509_new_null();
    crls = sk_X509_CRL_new_null();
    if (store == NULL || untrusted == NULL || crls == NULL)
    {
        goto exit;
    }

    for (i = 0; i < count; i++)
    {
        X509 *cert;

        if (sizes[i] <= 0 || (size_t) sizes[i] > der_len - off)
        {
            ret = JO_INPUT_TOO_LONG_INT32;
            goto exit;
        }
        cert = decode_bound(der + off, sizes[i]);
        off += (size_t) sizes[i];
        if (cert == NULL)
        {
            /* depth carries the index so the Java layer can name the
               certificate; nothing else populates it on this path. */
            result->depth = i;
            ret = JO_CERT_DECODE_FAILED;
            goto exit;
        }

        if (i < anchor_count)
        {
            if (X509_STORE_add_cert(store, cert) != 1)
            {
                X509_free(cert);
                goto exit;
            }
            X509_free(cert);   /* the store took its own reference */
        }
        else if (i == count - 1)
        {
            target = cert;
        }
        else if (sk_X509_push(untrusted, cert) <= 0)
        {
            X509_free(cert);
            goto exit;
        }
    }

    for (i = 0; i < crl_count; i++)
    {
        X509_CRL *crl;
        int32_t len = sizes[count + i];

        if (len <= 0 || (size_t) len > der_len - off)
        {
            ret = JO_INPUT_TOO_LONG_INT32;
            goto exit;
        }
        crl = decode_bound_crl(der + off, len);
        off += (size_t) len;
        if (crl == NULL)
        {
            /* depth carries the CRL's index among the CRLs, so the Java
               layer can name it; nothing else populates it on this path. */
            result->depth = i;
            ret = JO_CRL_DECODE_FAILED;
            goto exit;
        }
        if (sk_X509_CRL_push(crls, crl) <= 0)
        {
            X509_CRL_free(crl);
            goto exit;
        }
    }

    ctx = X509_STORE_CTX_new_ex(get_global_jostle_ossl_lib_ctx(), NULL);
    if (ctx == NULL || X509_STORE_CTX_init(ctx, store, target, untrusted) != 1)
    {
        goto exit;
    }
    /*
     * set0 by name, but X509_STORE_CTX_set0_crls only assigns and the cleanup
     * never frees it (x509_vfy.c, 3.1.2 :2197/:2333, 3.5.8 :2384/:2523), so
     * the stack stays OURS to free.
     */
    X509_STORE_CTX_set0_crls(ctx, crls);

    {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        unsigned long flags = X509_V_FLAG_PARTIAL_CHAIN;

        /*
         * PARTIAL_CHAIN is not optional: JCE anchor semantics let a chain
         * terminate at ANY trusted certificate, while OpenSSL without it
         * demands a self-signed root — so a non-self-signed TrustAnchor would
         * fail for a reason that has nothing to do with the path.
         */
        if (strict != 0)
        {
            flags |= X509_V_FLAG_X509_STRICT;
        }
        /*
         * All three are load-bearing, measured over PKITS's 109 revocation
         * cases: without CRL_CHECK_ALL the revoked INTERMEDIATE of 4.4.2 is
         * accepted, and EXTENDED_CRL_SUPPORT decides the 9 indirect-CRL and
         * separate-CRL-key cases.
         */
        if (revocation != 0)
        {
            flags |= X509_V_FLAG_CRL_CHECK
                     | X509_V_FLAG_CRL_CHECK_ALL
                     | X509_V_FLAG_EXTENDED_CRL_SUPPORT;
        }
        X509_VERIFY_PARAM_set_flags(param, flags);
        if (time_secs != CERTPATH_TIME_NOW)
        {
            X509_STORE_CTX_set_time(ctx, 0, (time_t) time_secs);
        }
    }

    ERR_clear_error();
    if (X509_verify_cert(ctx) == 1)
    {
        result->error = X509_V_OK;
    }
    else
    {
        result->error = X509_STORE_CTX_get_error(ctx);
        result->depth = X509_STORE_CTX_get_error_depth(ctx);
        if (result->error == X509_V_OK)
        {
            /* Reported failure yet no code: surface it rather than hide it. */
            result->error = X509_V_ERR_UNSPECIFIED;
        }
    }

    ret = capture_chain(ctx, result);

exit:
    X509_STORE_CTX_free(ctx);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    sk_X509_pop_free(untrusted, X509_free);
    X509_STORE_free(store);
    X509_free(target);
    if (ret != JO_SUCCESS)
    {
        /* Frees the buffers but leaves error/depth, which the bridge reports. */
        certpath_result_free(result);
    }
    return ret;
}

void certpath_result_free(certpath_result *result)
{
    if (result == NULL)
    {
        return;
    }
    OPENSSL_free(result->chain_der);
    OPENSSL_free(result->chain_sizes);
    result->chain_der = NULL;
    result->chain_sizes = NULL;
    result->chain_len = 0;
    result->chain_count = 0;
}
