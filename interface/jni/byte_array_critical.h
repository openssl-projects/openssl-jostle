//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

//
//

#ifndef BYTEARRAYCRITICAL_H
#define BYTEARRAYCRITICAL_H


#include <stddef.h>
#include <jni.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t *critical;
    size_t size;
    JNIEnv *env;
    jbyteArray array;
} critical_bytearray_ctx;




void init_critical_ctx(critical_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array);


/**
 * Actually claim the byte ctx from the jvm if not already claimed.
 * @param ctx pointer to the java_bytearray_ctx
 * @return non-zero on success
 */
bool load_critical_ctx(critical_bytearray_ctx *ctx);


/**
 * release_bytearray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_critical_ctx(critical_bytearray_ctx *ctx);

/**
 * Check the offset and length are wholly within the critical region
 * @param ctx the region
 * @param offset the nominated offset
 * @param len  the nominate len
 * @return true if within range or false
 */
bool check_critical_in_range(critical_bytearray_ctx *ctx, size_t offset, size_t len);

#endif //BYTEARRAYCRITICAL_H
