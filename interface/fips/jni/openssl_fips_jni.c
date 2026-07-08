//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <jni.h>
#include <openssl/bio.h>

#include "org_openssl_jostle_jcajce_provider_fips_OpenSSLFIPSJNI.h"
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

#include "rand_upcall_jni.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/rand.h"
#include "../util/rand/jostle_fips_ctx.h"
#include "../util/rand/jostle_lib_ctx.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_fips_OpenSSLFIPSJNI
 * Method:    setOSSLFIPSModule
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 *
 * Initialises this library's own global lib ctx AND the SecureRandom-backing
 * rand lib ctx, both with the OpenSSL FIPS module + base provider. The FIPS
 * module is dlopen'd by libcrypto itself - never System.load'ed.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_fips_OpenSSLFIPSJNI_setOSSLFIPSModule(
    JNIEnv *env, jobject jo, jstring _module_dir, jstring _prov_name, jstring _config_path) {
    UNUSED(jo);

    const char *module_dir = NULL;
    const char *prov_name = NULL;
    const char *config_path = NULL;
    int result = JO_FAIL;

    if (_module_dir == NULL || (*env)->GetStringLength(env, _module_dir) == 0) {
        result = JO_FIPS_MODULE_PATH_INVALID;
        goto exit;
    }

    if (_prov_name == NULL) {
        result = JO_PROV_NAME_NULL;
        goto exit;
    }
    if ((*env)->GetStringLength(env, _prov_name) == 0) {
        result = JO_PROV_NAME_EMPTY;
        goto exit;
    }

    if (_config_path == NULL || (*env)->GetStringLength(env, _config_path) == 0) {
        result = JO_FIPS_CONFIG_PATH_INVALID;
        goto exit;
    }

    module_dir = (*env)->GetStringUTFChars(env, _module_dir, NULL);
    if (module_dir == NULL) {
        result = JO_FAIL;
        goto exit;
    }
    prov_name = (*env)->GetStringUTFChars(env, _prov_name, NULL);
    if (prov_name == NULL) {
        result = JO_FAIL;
        goto exit;
    }
    config_path = (*env)->GetStringUTFChars(env, _config_path, NULL);
    if (config_path == NULL) {
        result = JO_FAIL;
        goto exit;
    }

    // Operations lib ctx first: jostle_ctx_init_fips creates a fresh lib ctx
    // per call and fails cleanly (rolled back) without touching global state,
    // so a bad config / wrong name surfaces the exact JO_FIPS_* code
    // regardless of whether a prior call already succeeded. The separate RAND
    // context (backing SecureRandomSpi, mirroring the base entry) is
    // initialised only after; its first-name-wins guard must not pre-empt the
    // operations-ctx failure codes.
    jostle_lib_ctx *provider_ctx = NULL;
    int32_t rand_created = 0;

    result = jostle_ctx_init_fips(&provider_ctx, module_dir, prov_name, config_path);
    if (UNSUCCESSFUL(result)) {
        goto exit;
    }

    result = rand_init_fips(module_dir, prov_name, config_path, &rand_created);
    if (UNSUCCESSFUL(result)) {
        jostle_ctx_destroy(provider_ctx);
        goto exit;
    }

    result = set_global_jostle_lib_ctx(provider_ctx);
    if (UNSUCCESSFUL(result)) {
        if (rand_created) {
            rand_destroy();
        }
        jostle_ctx_destroy(provider_ctx);
        goto exit;
    }

    // Cache the RandSource up-call target machinery. The FIPS lib ctx does
    // not install the java_rand_bridge RAND, so entropy up-calls never fire
    // from it; this keeps the bridge entry points that set the thread-local
    // functional and symmetric with the base library.
    rand_up_call_init_jni(env);

exit:
    if (module_dir != NULL) {
        (*env)->ReleaseStringUTFChars(env, _module_dir, module_dir);
    }
    if (prov_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _prov_name, prov_name);
    }
    if (config_path != NULL) {
        (*env)->ReleaseStringUTFChars(env, _config_path, config_path);
    }
    return result;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_fips_OpenSSLFIPSJNI
 * Method:    getOSSLErrors
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_openssl_jostle_jcajce_provider_fips_OpenSSLFIPSJNI_getOSSLErrors
(JNIEnv *env, jobject jo) {
    UNUSED(jo);

    BIO *bio = BIO_new(BIO_s_mem());

    if (bio == NULL) {
        return (*env)->NewStringUTF(env, "bio was null");
    }

    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *) calloc(1, 1 + len); // Overallocating by 1 to add trailing zero
    jo_assert(ret != NULL);
    memcpy(ret, buf, len);
    BIO_free(bio);

    /* Create java string */
    jstring str = (*env)->NewStringUTF(env, ret);
    free(ret);
    return str;
}
