//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <jni.h>
#include <openssl/bio.h>

#include "org_openssl_jostle_jcajce_provider_OpenSSLJNI.h"
#include <openssl/provider.h>
#include <openssl/err.h>
#include <string.h>

#include "types.h"
#include "../util/bc_err_codes.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_OpenSSLJNI
 * Method:    setOSSLProviderModule
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_OpenSSLJNI_setOSSLProviderModule(
    JNIEnv *env, jclass cl, jstring _prov_name) {
    UNUSED(env);
    UNUSED(cl);

    const char *prov_name = NULL;
    OSSL_PROVIDER *loaded_provider = NULL;;
    int result = JO_FAIL;


    if (_prov_name == NULL) {
        result = JO_PROV_NAME_NULL;
        goto exit;
    }

    jsize len = (*env)->GetStringLength(env, _prov_name);

    if (len == 0) {
        result = JO_PROV_NAME_EMPTY;
        goto exit;
    }

    prov_name = (*env)->GetStringUTFChars(env, _prov_name, NULL);

    // Operate on default OSSL_LIB_CTX
    loaded_provider = OSSL_PROVIDER_load(NULL, prov_name);
    if (loaded_provider == NULL) {
        result = JO_OPENSSL_ERROR;
    }

exit:
    if (prov_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _prov_name, prov_name);
    }
    return result;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_OpenSSLJNI
 * Method:    getOSSLErrors
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_openssl_jostle_jcajce_provider_OpenSSLJNI_getOSSLErrors
(JNIEnv *env, jclass cl) {
    UNUSED(env);
    UNUSED(cl);

    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *) calloc(1, 1 + len); // Overallocating by 1 to add trailing zero
    assert(ret != NULL);
    memcpy(ret, buf, len);
    BIO_free(bio);

    /* Create java string */
    jstring str = (*env)->NewStringUTF(env, ret);
    free(ret);
    return str;
}
