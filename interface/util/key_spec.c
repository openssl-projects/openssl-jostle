//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#include "key_spec.h"

#include <assert.h>
#include <stdlib.h>
#include <openssl/evp.h>


key_spec *create_spec(void) {
    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));
    assert(spec != NULL);
    return spec;
}

/*
 * free the underlying PKEY, this may be done at the exit of a try catch block for a key
 */
void free_spec(key_spec *spec) {
    assert(spec != NULL);
    EVP_PKEY_free(spec->key);
    spec->key = NULL;
}

/*
 * free the key_spec and also freeing the PKEY if not already done so.
 * this would be normally called by the disposal daemon.
 */
void free_key_spec(key_spec *spec) {
    if (spec == NULL) {
        return;
    }
    free_spec(spec);
    OPENSSL_clear_free(spec, sizeof(*spec));
}
