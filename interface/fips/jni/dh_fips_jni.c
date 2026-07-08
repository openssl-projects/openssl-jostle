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
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1allocateKex                Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1allocateKex
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1disposeKex                 Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1disposeKex
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1generateKeyPair            Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1generateKeyPair
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1generateKeyPairByGroup     Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1generateKeyPairByGroup
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1generateParameters         Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1generateParameters
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1getComponent               Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1getComponent
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1groupSupported             Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1groupSupported
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1kexDerive                  Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1kexDerive
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1kexInit                    Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1kexInit
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1kexSetPeer                 Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1kexSetPeer
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1makeParamsFromComponents   Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1makeParamsFromComponents
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1makePrivateFromComponents  Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1makePrivateFromComponents
#define Java_org_openssl_jostle_jcajce_provider_dh_DHServiceJNI_ni_1makePublicFromComponents   Java_org_openssl_jostle_jcajce_provider_fips_DHServiceFIPSJNI_ni_1makePublicFromComponents
/* *INDENT-ON* */

#include "dh_ni_jni.c"
