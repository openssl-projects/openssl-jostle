//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "openssl_ffi.h"


#include <stddef.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/types.h>
#include <string.h>
#include "../util/jo_assert.h"
#include "../util/rand/jostle_lib_ctx.h"


/*
* set the openssl module
*/
int32_t set_openssl_module(const char *prov_name /* JVM */) {
    int32_t result = JO_FAIL;

    if (prov_name == NULL) {
        result = JO_PROV_NAME_NULL;
        goto exit;
    }

    if (*prov_name == '\0') {
        result = JO_PROV_NAME_EMPTY;
        goto exit;
    }


    // jostle_ctx_init_new owns rnd: allocates on entry, frees on failure.
    jostle_lib_ctx *rnd = NULL;


    result = jostle_ctx_init_new(&rnd, prov_name);
    if (UNSUCCESSFUL(result)) {
        // rnd is NULL: init_new freed it.
        goto exit;
    }

    result = set_global_jostle_lib_ctx(rnd);

    if (UNSUCCESSFUL(result)) {
        // rnd owns libctx + providers + rand_ctx; plain OPENSSL_free leaks them.
        jostle_ctx_destroy(rnd);
    }



exit:
    return result;
}

/*
* return any available openssl errors
*/
char *get_ossl_errors(uint64_t *len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        // Allocation failure: return a usable diagnostic string instead of
        // crashing in ERR_print_errors below. Caller frees.
        static const char msg[] = "bio was null";
        *len = sizeof(msg);
        char *ret = calloc(*len, 1);
        jo_assert(ret != NULL);
        memcpy(ret, msg, sizeof(msg));
        return ret;
    }
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t size = BIO_get_mem_data(bio, &buf);
    *len = size + 1; // Overallocating by 1 to add trailing zero
    char *ret = calloc(*len, 1);
    jo_assert(ret != NULL);
    memcpy(ret, buf, size);
    BIO_free(bio);
    return ret; /* Now, Owned by Java side. */
}
