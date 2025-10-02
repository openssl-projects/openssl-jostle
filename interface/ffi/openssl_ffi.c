//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#include "openssl_ffi.h"

#include <assert.h>
#include <stddef.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/types.h>
#include <string.h>


/*
* set the openssl module
*/
int32_t set_openssl_module(const char *prov_name /* JVM */) {
    int32_t result = JO_FAIL;
    OSSL_PROVIDER *loaded_provider = NULL;;

    if (prov_name == NULL) {
        result = JO_PROV_NAME_NULL;
        goto exit;
    }

    if (*prov_name == '\0') {
        result = JO_PROV_NAME_EMPTY;
        goto exit;
    }

    loaded_provider = OSSL_PROVIDER_load(NULL, prov_name);
    if (loaded_provider == NULL) {
        result = JO_OPENSSL_ERROR;
    }

exit:
    return result;
}

/*
* return any available openssl errors
*/
char *get_ossl_errors(uint64_t *len) {
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t size = BIO_get_mem_data(bio, &buf);
    *len = size + 1; // Overallocating by 1 to add trailing zero
    char *ret = calloc(*len, 1);
    assert(ret != NULL);
    memcpy(ret, buf, size);
    BIO_free(bio);
    return ret; /* Now, Owned by Java side. */
}
