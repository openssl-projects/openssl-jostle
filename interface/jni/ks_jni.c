//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <jni.h>
#include <stdint.h>

#include <openssl/crypto.h>

#include "bytearrays.h"
#include "types.h"
#include "../util/ks.h"
#include "../util/ops.h"
#include "../util/jo_assert.h"
#include "org_openssl_jostle_jcajce_provider_ks_KSServiceJNI.h"

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1allocateKeyStore
(JNIEnv *env, jobject self, jstring _type, jintArray _err) {
    const char *type = NULL;
    int32_t *err = NULL;
    ks_ctx *ctx = NULL;

    UNUSED(self);

    if (_err == NULL) {
        return 0;
    }

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (_type == NULL) {
        *err = JO_KS_TYPE_IS_NULL;
        goto exit;
    }

    type = (*env)->GetStringUTFChars(env, _type, NULL);
    if (OPS_FAILED_ACCESS_1 type == NULL) {
        *err = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    ctx = ks_allocate(type, err);

exit:
    if (type != NULL) {
        (*env)->ReleaseStringUTFChars(env, _type, type);
    }
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return (jlong) ctx;
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1dispose
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    ks_free((ks_ctx *) ref);
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1load
(JNIEnv *env, jobject self, jlong ref, jbyteArray _input, jbyteArray _password) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    java_bytearray_ctx input;
    java_bytearray_ctx password;
    int32_t ret;

    init_bytearray_ctx(&input);
    init_bytearray_ctx(&password);

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&password, env, _password)) {
        ret = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    ret = ks_load(ctx, input.bytearray, input.size, password.bytearray, password.size);

exit:
    release_bytearray_ctx(&input);
    release_bytearray_ctx(&password);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1store
(JNIEnv *env, jobject self, jlong ref, jbyteArray _password, jintArray _err) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    java_bytearray_ctx password;
    int32_t *err = NULL;
    uint8_t *out = NULL;
    size_t out_len = 0;
    jbyteArray result = NULL;

    init_bytearray_ctx(&password);

    if (_err == NULL) {
        return NULL;
    }

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&password, env, _password)) {
        *err = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    *err = ks_store(ctx, &out, &out_len, password.bytearray, password.size);
    if (UNSUCCESSFUL(*err)) {
        goto exit;
    }

    if (OPS_INT32_OVERFLOW_1 out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }

    result = (*env)->NewByteArray(env, (jsize) out_len);
    if (result == NULL) {
        *err = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize) out_len, (jbyte *) out);

exit:
    if (out != NULL) {
        OPENSSL_clear_free(out, out_len);
    }
    release_bytearray_ctx(&password);
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1getKey
(JNIEnv *env, jobject self, jlong ref, jstring _alias, jbyteArray _password, jintArray _err) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    java_bytearray_ctx password;
    int32_t *err = NULL;
    uint8_t *out = NULL;
    size_t out_len = 0;
    jbyteArray result = NULL;

    init_bytearray_ctx(&password);

    if (_err == NULL) {
        return NULL;
    }

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        goto exit;
    }

    if (_alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        goto exit;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        *err = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&password, env, _password)) {
        *err = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    *err = ks_get_key(ctx, alias, &out, &out_len,
            password.bytearray, password.size);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }

    if (OPS_INT32_OVERFLOW_2 out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }

    result = (*env)->NewByteArray(env, (jsize) out_len);
    if (result == NULL) {
        *err = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize) out_len, (jbyte *) out);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    if (out != NULL) {
        OPENSSL_clear_free(out, out_len);
    }
    release_bytearray_ctx(&password);
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return result;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1setKey
(JNIEnv *env, jobject self, jlong ref, jstring _alias, jbyteArray _key, jbyteArray _password) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    java_bytearray_ctx key;
    java_bytearray_ctx password;
    int32_t ret;

    init_bytearray_ctx(&key);
    init_bytearray_ctx(&password);

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    if (_key == NULL) {
        ret = JO_KS_KEY_IS_NULL;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&key, env, _key)) {
        ret = JO_KS_FAILED_ACCESS_KEY;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_bytearray_ctx(&password, env, _password)) {
        ret = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    ret = ks_set_key(ctx, alias, key.bytearray, key.size,
            password.bytearray, password.size);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&password);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1getCertificateChain
(JNIEnv *env, jobject self, jlong ref, jstring _alias, jintArray _err) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    int32_t *err = NULL;
    uint8_t *out = NULL;
    size_t out_len = 0;
    jbyteArray result = NULL;

    if (_err == NULL) {
        return NULL;
    }

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        goto exit;
    }

    if (_alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        goto exit;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        *err = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    *err = ks_get_certificate_chain(ctx, alias, &out, &out_len);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }

    if (OPS_INT32_OVERFLOW_2 out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }

    result = (*env)->NewByteArray(env, (jsize) out_len);
    if (result == NULL) {
        *err = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize) out_len, (jbyte *) out);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    if (out != NULL) {
        OPENSSL_clear_free(out, out_len);
    }
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return result;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1setCertificateChain
(JNIEnv *env, jobject self, jlong ref, jstring _alias, jbyteArray _chain) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    java_bytearray_ctx chain;
    int32_t ret;

    init_bytearray_ctx(&chain);

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    if (_chain != NULL && OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&chain, env, _chain)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret = ks_set_certificate_chain(ctx, alias, chain.bytearray, chain.size);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    release_bytearray_ctx(&chain);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1setCertificateEntry
(JNIEnv *env, jobject self, jlong ref, jstring _alias, jbyteArray _certificate) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    java_bytearray_ctx certificate;
    int32_t ret;

    init_bytearray_ctx(&certificate);

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    if (_certificate != NULL && OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&certificate, env, _certificate)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret = ks_set_certificate_entry(ctx, alias, certificate.bytearray, certificate.size);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    release_bytearray_ctx(&certificate);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1deleteEntry
(JNIEnv *env, jobject self, jlong ref, jstring _alias) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    ret = ks_delete_entry(ctx, alias);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1getAliases
(JNIEnv *env, jobject self, jlong ref, jintArray _err) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    int32_t *err = NULL;
    uint8_t *out = NULL;
    size_t out_len = 0;
    jbyteArray result = NULL;

    if (_err == NULL) {
        return NULL;
    }

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        goto exit;
    }

    *err = ks_get_aliases(ctx, &out, &out_len);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }

    if (OPS_INT32_OVERFLOW_1 out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }

    result = (*env)->NewByteArray(env, (jsize) out_len);
    if (result == NULL) {
        *err = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize) out_len, (jbyte *) out);

exit:
    if (out != NULL) {
        OPENSSL_clear_free(out, out_len);
    }
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return result;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1containsAlias
(JNIEnv *env, jobject self, jlong ref, jstring _alias) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    ret = ks_contains_alias(ctx, alias);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1size
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    return ks_size(ctx);
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1isKeyEntry
(JNIEnv *env, jobject self, jlong ref, jstring _alias) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    ret = ks_is_key_entry(ctx, alias);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1isCertificateEntry
(JNIEnv *env, jobject self, jlong ref, jstring _alias) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (_alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        ret = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    ret = ks_is_certificate_entry(ctx, alias);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    return ret;
}

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ks_KSServiceJNI_ni_1getCreationDate
(JNIEnv *env, jobject self, jlong ref, jstring _alias, jintArray _err) {
    UNUSED(self);

    ks_ctx *ctx = (ks_ctx *) ref;
    const char *alias = NULL;
    int32_t *err = NULL;
    int64_t ret = 0;

    if (_err == NULL) {
        return 0;
    }

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        goto exit;
    }

    if (_alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        goto exit;
    }

    alias = (*env)->GetStringUTFChars(env, _alias, NULL);
    if (OPS_FAILED_ACCESS_1 alias == NULL) {
        *err = JO_KS_UNABLE_TO_ACCESS_ALIAS;
        goto exit;
    }

    ret = ks_get_creation_date(ctx, alias, err);

exit:
    if (alias != NULL) {
        (*env)->ReleaseStringUTFChars(env, _alias, alias);
    }
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return (jlong) ret;
}
