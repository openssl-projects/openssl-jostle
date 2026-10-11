//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "secret_bytearrays.h"

#include <string.h>
#include <openssl/crypto.h>

#include "../util/jo_assert.h"
#include "../util/ops.h"

void init_secret_bytearray_ctx(java_secret_bytearray_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    ctx->bytearray = NULL;
    ctx->size = 0;
    ctx->env = NULL;
    ctx->array = NULL;
    ctx->kind = JO_SECRET_NONE;
    ctx->jvm_copy = JNI_FALSE;
    ctx->cleansed = 0;
}

static void reset(java_secret_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array, int kind) {
    jo_assert(ctx != NULL);
    init_secret_bytearray_ctx(ctx);
    ctx->env = env;
    ctx->array = array;
    ctx->kind = kind;
}

/* Leaves an OutOfMemoryError pending; if FindClass fails, its own exception is pending instead. */
static void throw_oom(JNIEnv *env) {
    jclass oom = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
    if (oom != NULL) {
        (*env)->ThrowNew(env, oom, "secret byte array copy");
    }
}

static void loaded(void) {
    JO_LEDGER_CREATED(JO_LEDGER_SECRET_BYTEARRAY);
    JO_LEDGER_CREATED(JO_LEDGER_SECRET_CLEANSE);
}

int load_secret_input_ctx(java_secret_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array) {
    reset(ctx, env, array, JO_SECRET_INPUT);
    if (array == NULL) {
        return 1;
    }

    ctx->size = (size_t) (*env)->GetArrayLength(env, array);
    jboolean is_copy = JNI_FALSE;
    jbyte *elements = (*env)->GetByteArrayElements(env, array, &is_copy);
    if (elements == NULL) {
        return 0;
    }

    if (is_copy) {
        ctx->bytearray = (uint8_t *) elements;
        ctx->jvm_copy = JNI_TRUE;
        loaded();
        return 1;
    }

    // The JVM handed us the array itself: copy it, then release the array unwritten.
    uint8_t *copy = OPENSSL_malloc(ctx->size > 0 ? ctx->size : 1);
    if (copy != NULL) {
        memcpy(copy, elements, ctx->size);
    }
    (*env)->ReleaseByteArrayElements(env, array, elements, JNI_ABORT);
    if (copy == NULL) {
        throw_oom(env);
        return 0;
    }
    ctx->bytearray = copy;
    loaded();
    return 1;
}

int load_secret_output_ctx(java_secret_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array) {
    reset(ctx, env, array, JO_SECRET_OUTPUT);
    if (array == NULL) {
        return 1;
    }

    ctx->size = (size_t) (*env)->GetArrayLength(env, array);
    uint8_t *buffer = OPENSSL_malloc(ctx->size > 0 ? ctx->size : 1);
    if (buffer == NULL) {
        throw_oom(env);
        return 0;
    }

    // Whole-array write-back at release: start from the array's content so unwritten bytes come back unchanged.
    (*env)->GetByteArrayRegion(env, array, 0, (jsize) ctx->size, (jbyte *) buffer);
    if ((*env)->ExceptionCheck(env)) {
        OPENSSL_clear_free(buffer, ctx->size);
        return 0;
    }
    ctx->bytearray = buffer;
    loaded();
    return 1;
}

bool check_secret_in_range(java_secret_bytearray_ctx *ctx, size_t offset, size_t len) {
    jo_assert(ctx != NULL);
    return (len <= ctx->size) && (offset <= ctx->size - len);
}

static void release_secret(java_secret_bytearray_ctx *ctx, bool write_back) {
    if (ctx == NULL || ctx->bytearray == NULL || ctx->env == NULL) {
        return;
    }
    JNIEnv *env = ctx->env;

    if (write_back && ctx->kind == JO_SECRET_OUTPUT && !(*env)->ExceptionCheck(env)) {
        (*env)->SetByteArrayRegion(env, ctx->array, 0, (jsize) ctx->size, (jbyte *) ctx->bytearray);
    }

    OPENSSL_cleanse(ctx->bytearray, ctx->size);
    JO_LEDGER_DESTROYED(JO_LEDGER_SECRET_CLEANSE);

#ifdef JOSTLE_OPS
    // Measured, not assumed: the bytes that read back as zero after the cleanse.
    ctx->cleansed = 0;
    for (size_t i = 0; i < ctx->size; i++) {
        if (ctx->bytearray[i] == 0) {
            ctx->cleansed++;
        }
    }
#endif

    if (ctx->jvm_copy) {
        (*env)->ReleaseByteArrayElements(env, ctx->array, (jbyte *) ctx->bytearray, JNI_ABORT);
    } else {
        OPENSSL_free(ctx->bytearray);
    }
    ctx->bytearray = NULL;
    ctx->jvm_copy = JNI_FALSE;
    JO_LEDGER_DESTROYED(JO_LEDGER_SECRET_BYTEARRAY);
}

void release_secret_bytearray_ctx(java_secret_bytearray_ctx *ctx) {
    release_secret(ctx, true);
}

void discard_secret_bytearray_ctx(java_secret_bytearray_ctx *ctx) {
    release_secret(ctx, false);
}
