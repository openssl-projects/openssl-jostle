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
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1allocateKex              Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1allocateKex
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1allocateSigner           Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1allocateSigner
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1curveSupported           Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1curveSupported
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1disposeKex               Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1disposeKex
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1disposeSigner            Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1disposeSigner
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1generateKeyPair          Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1generateKeyPair
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1getComponent             Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1getComponent
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1initSign                 Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1initSign
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1initVerify               Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1initVerify
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1kexDerive                Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1kexDerive
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1kexInit                  Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1kexInit
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1kexSetPeer               Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1kexSetPeer
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1makePrivateFromComponents Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1makePrivateFromComponents
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1sign                     Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1sign
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1update                   Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1update
#define Java_org_openssl_jostle_jcajce_provider_ec_ECServiceJNI_ni_1verify                   Java_org_openssl_jostle_jcajce_provider_fips_ECServiceFIPSJNI_ni_1verify
/* *INDENT-ON* */

#include "ec_ni_jni.c"
