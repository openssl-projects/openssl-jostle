//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef SECRET_BYTEARRAYS_H
#define SECRET_BYTEARRAYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <jni.h>

// Byte arrays carrying secrets. C only ever touches memory it cleanses before release, and an input's Java
// array is never written. A distinct type, so the plain release cannot be applied to one.
// No critical variant: a critical pointer is the Java array itself, so cleansing it would wipe the caller's array.

#define JO_SECRET_NONE 0     /* a ctx not yet loaded; never a loaded kind */
#define JO_SECRET_INPUT 1
#define JO_SECRET_OUTPUT 2

typedef struct {
    uint8_t *bytearray;
    size_t size;
    JNIEnv *env;
    jbyteArray array;
    int kind;
    jboolean jvm_copy;
    size_t cleansed;
} java_secret_bytearray_ctx;

/**
 * Sets every field to NULL or 0; release is then a no-op. NULL-safe.
 */
void init_secret_bytearray_ctx(java_secret_bytearray_ctx *ctx);

/**
 * Read-only input. bytearray is the JVM's copy when the JVM made one, otherwise our own copy, the Java
 * array having been released unwritten. A NULL array gives size 0, bytearray NULL and returns 1.
 * A refused Get or allocation returns 0 with a JNI exception pending; the caller returns to Java with no
 * further JNI call.
 */
int load_secret_input_ctx(java_secret_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array);

/**
 * Output. bytearray is our own buffer holding the Java array's current content, written back whole at
 * release, so bytes C does not write return unchanged. NULL array and failure as for input.
 */
int load_secret_output_ctx(java_secret_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array);

/**
 * True if offset and len lie within the array.
 */
bool check_secret_in_range(java_secret_bytearray_ctx *ctx, size_t offset, size_t len);

/**
 * Output: writes the buffer back unless a JNI exception is pending. Then cleanses and frees (or releases the
 * JVM copy with JNI_ABORT). NULL-safe, and a no-op for a NULL array or a failed load.
 */
void release_secret_bytearray_ctx(java_secret_bytearray_ctx *ctx);

#endif //SECRET_BYTEARRAYS_H
