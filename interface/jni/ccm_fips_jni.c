//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for CCMCipherFIPSJNI: the base glue re-included
// under the FIPS class's symbols (see md_fips_jni.c for the pattern
// rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes ccm_ni_jni.c itself);
// the base interface_jni compiles ccm_ni_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1makeInstance   Java_org_openssl_jostle_jcajce_provider_fips_CCMCipherFIPSJNI_ni_1makeInstance
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1dispose        Java_org_openssl_jostle_jcajce_provider_fips_CCMCipherFIPSJNI_ni_1dispose
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1init           Java_org_openssl_jostle_jcajce_provider_fips_CCMCipherFIPSJNI_ni_1init
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1doFinal        Java_org_openssl_jostle_jcajce_provider_fips_CCMCipherFIPSJNI_ni_1doFinal
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_CCMCipherJNI_ni_1getOutputSize  Java_org_openssl_jostle_jcajce_provider_fips_CCMCipherFIPSJNI_ni_1getOutputSize
/* *INDENT-ON* */

#include "ccm_ni_jni.c"
