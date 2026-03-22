// Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
// Licensed under Apache 2.0
#ifndef JO_DIGEST_NI_FFI_H
#define JO_DIGEST_NI_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Create a new digest context for the given canonical OpenSSL algorithm name
// Returns JO_SUCCESS on success and writes an opaque pointer value to out_ctx
int32_t jo_digest_new(const char *canonical_name, uintptr_t *out_ctx);

// Update the digest with input bytes starting at in+off of length len
int32_t jo_digest_update(uintptr_t ctx, const uint8_t *in, int32_t off, int32_t len);

// Finalize the digest into out+off. Returns number of bytes written or error code (<0)
int32_t jo_digest_final(uintptr_t ctx, uint8_t *out, int32_t off, int32_t out_len);

// Get the digest length (in bytes) for the context
int32_t jo_digest_len(uintptr_t ctx);

// Reset the digest context to initial state
void jo_digest_reset(uintptr_t ctx);

// Free the digest context
void jo_digest_free(uintptr_t ctx);

// Copy an existing digest context (deep copy), result in out_ctx
int32_t jo_digest_copy(uintptr_t ctx, uintptr_t *out_ctx);

// Set an OpenSSL property query string to use when fetching algorithms
int32_t jo_digest_set_props(const char *props);

#ifdef __cplusplus
}
#endif

#endif // JO_DIGEST_NI_FFI_H
