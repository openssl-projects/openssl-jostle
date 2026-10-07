//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <jni.h>
#include "org_openssl_jostle_NativeServiceJNI.h"
#include "openssl/opensslconf.h"
#include <openssl/crypto.h>
#include "types.h"


/*
 * Class:     org_openssl_jostle_NativeInfo
 * Method:    nativeAvailable
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_org_openssl_jostle_NativeServiceJNI_nativeAvailable
(JNIEnv *env, jclass cl) {
    UNUSED(env);
    UNUSED(cl);
    return JNI_TRUE;
}


/*
 * Class:     org_openssl_jostle_NativeInfo
 * Method:    openSSLVersion
 * Signature: ()Ljava/lang/String;
 *
 * The libcrypto loaded at runtime, which need not be the one the headers came from.
 */
JNIEXPORT jstring JNICALL Java_org_openssl_jostle_NativeServiceJNI_openSSLVersion
(JNIEnv *env, jclass cl) {
    UNUSED(cl);
    return (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
}


/*
 * Class:     org_openssl_jostle_NativeInfo
 * Method:    openSSLBuildVersion
 * Signature: ()Ljava/lang/String;
 *
 * The OpenSSL headers this library was compiled against.
 */
JNIEXPORT jstring JNICALL Java_org_openssl_jostle_NativeServiceJNI_openSSLBuildVersion
(JNIEnv *env, jclass cl) {
    UNUSED(cl);
    return (*env)->NewStringUTF(env, OPENSSL_FULL_VERSION_STR);
}
