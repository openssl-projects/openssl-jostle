//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "key_spec.h"


#include <stdlib.h>
#include <openssl/evp.h>

#include "jo_assert.h"
#include "ops.h"


key_spec *create_spec(void) {
    key_spec *spec = OPENSSL_zalloc(sizeof(key_spec));
    jo_assert(spec != NULL);
    JO_LEDGER_CREATED(JO_LEDGER_KEY_SPEC);
    return spec;
}

/*
 * free the underlying PKEY only.
 * Internal helper used by free_key_spec; caller must have null-checked spec.
 */
static void free_spec(key_spec *spec) {
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
    JO_LEDGER_DESTROYED(JO_LEDGER_KEY_SPEC);
    free_spec(spec);
    OPENSSL_clear_free(spec, sizeof(*spec));
}
