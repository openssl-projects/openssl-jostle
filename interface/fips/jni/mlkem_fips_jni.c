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
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1decode_1privateKey                                             Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1decode_1privateKey
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1decode_1publicKey                                              Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1decode_1publicKey
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1generateKeyPair__I_3ILorg_openssl_jostle_rand_RandSource_2     Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1generateKeyPair__I_3ILorg_openssl_jostle_rand_RandSource_2
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1generateKeyPair__I_3I_3BILorg_openssl_jostle_rand_RandSource_2 Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1generateKeyPair__I_3I_3BILorg_openssl_jostle_rand_RandSource_2
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1getPrivateKey                                                  Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1getPrivateKey
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1getPublicKey                                                   Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1getPublicKey
#define Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_ni_1getSeed                                                        Java_org_openssl_jostle_jcajce_provider_fips_MLKEMServiceFIPSJNI_ni_1getSeed
/* *INDENT-ON* */

#include "mlkem_ni_jni.c"
