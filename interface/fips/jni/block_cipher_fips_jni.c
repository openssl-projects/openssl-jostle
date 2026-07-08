//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for BlockCipherFIPSJNI: the base glue
// re-included under the FIPS class's symbols (see md_fips_jni.c for the
// pattern rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes block_cipher_ni_jni.c
// itself); the base interface_jni compiles block_cipher_ni_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1makeInstance   Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1makeInstance
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1init           Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1init
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1getBlockSize   Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1getBlockSize
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1update         Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1update
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1doFinal        Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1doFinal
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1updateAAD      Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1updateAAD
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1getFinalSize   Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1getFinalSize
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1getUpdateSize  Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1getUpdateSize
#define Java_org_openssl_jostle_jcajce_provider_blockcipher_BlockCipherJNI_ni_1dispose        Java_org_openssl_jostle_jcajce_provider_fips_BlockCipherFIPSJNI_ni_1dispose
/* *INDENT-ON* */

#include "block_cipher_ni_jni.c"
