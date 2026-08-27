//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue: the base bridge re-included under the FIPS
// class's symbols (see md_fips_jni.c for the pattern rationale). This file
// must only ever contain renames.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1decode_1privateKey Java_org_openssl_jostle_jcajce_provider_fips_MLXKEMServiceFIPSJNI_ni_1decode_1privateKey
#define Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1decode_1publicKey  Java_org_openssl_jostle_jcajce_provider_fips_MLXKEMServiceFIPSJNI_ni_1decode_1publicKey
#define Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1generateKeyPair    Java_org_openssl_jostle_jcajce_provider_fips_MLXKEMServiceFIPSJNI_ni_1generateKeyPair
#define Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1getPrivateKey      Java_org_openssl_jostle_jcajce_provider_fips_MLXKEMServiceFIPSJNI_ni_1getPrivateKey
#define Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1getPublicKey       Java_org_openssl_jostle_jcajce_provider_fips_MLXKEMServiceFIPSJNI_ni_1getPublicKey
/* *INDENT-ON* */

#include "mlxkem_ni_jni.c"
