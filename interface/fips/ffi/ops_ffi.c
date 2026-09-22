//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// Jo-prefixed FFI entry points for the operations-test surface.
//
// Every FFI export the Java layer resolves carries a Jo prefix, so that the
// dynamic loader cannot confuse one with a libcrypto export and so the FIPS
// tree's rename wrappers have a uniform surface to work on. The underlying
// set_ops_test / OPS_GetRandomBytes live in util/ops.c, which is shared with
// the JNI bridge (jni/ops.c calls them directly) - renaming them there would
// churn the JNI side for no gain, so the FFI surface forwards instead.
//
// Only present in JOSTLE_OPS builds, matching util/ops.c.
//

#include <stdint.h>
#include "../util/ops.h"
#include "../util/rand.h"

#ifdef JOSTLE_OPS

void JoOps_setFlag(const uint32_t index, const uint32_t value)
{
    set_ops_test(index, value);
}

int JoOps_getRandomBytes(uint8_t *buf, size_t len, int32_t strength, int32_t pred, void *rnd_src)
{
    return OPS_GetRandomBytes(buf, len, strength, pred, rnd_src);
}

// The handle is an ordinary rand context; the Java side drives it through
// RandServiceNI. Forwarding rather than renaming rand_ctx_create_test in
// util/rand.c, which the JNI bridge calls directly.
void *JoOps_createTestDrbg(const char *mechanism, const char *variant, int32_t use_df,
                           int32_t strength, int32_t pred,
                           const uint8_t *personalization, size_t personalization_len,
                           const uint8_t *entropy, size_t entropy_len,
                           const uint8_t *nonce, size_t nonce_len, int32_t *err)
{
    return (void *) rand_ctx_create_test(mechanism, variant, use_df, strength, pred,
                                         personalization, personalization_len,
                                         entropy, entropy_len, nonce, nonce_len, err);
}

#endif
