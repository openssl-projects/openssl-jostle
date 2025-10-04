//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//

#ifndef BYTEARRAYS_H
#define BYTEARRAYS_H

#include <stdbool.h>
#include "jni.h"
#include <stdint.h>

typedef struct {
    uint8_t *bytearray;
    size_t size;
    JNIEnv *env;
    jbyteArray array;
} java_bytearray_ctx;


/**
 * Init a byte array context setting values to null.
 * It is safe to call release_bytearray_ctx after applying this function.
 * @param ctx
 */
void init_bytearray_ctx(java_bytearray_ctx *ctx);

/**
 * Load a java byte array and claim it from the jvm
 * @param env
 * @param array
 * @return
 */
int load_bytearray_ctx(java_bytearray_ctx *ctx, JNIEnv *env, jbyteArray array);

/**
 * returns true if the offset and len are within the bytearray region.
 */
bool check_bytearray_in_range(java_bytearray_ctx *ctx, size_t offset, size_t len);



/**
 * release_bytearray_ctx releases a java byte ctx back to the jvm
 * null safe and unclaimed safe.
 * @param ctx
 */
void release_bytearray_ctx(java_bytearray_ctx *ctx);

#endif //BYTEARRAYS_H
