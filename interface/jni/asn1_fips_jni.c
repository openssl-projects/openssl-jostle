//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for Asn1FIPSJNI: the base glue re-included
// under the FIPS class's symbols (see md_fips_jni.c for the pattern
// rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes asn1_ni_jni.c
// itself); the base interface_jni compiles asn1_ni_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1allocate            Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1allocate
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1dispose             Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1dispose
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1encodePublicKey     Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1encodePublicKey
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1encodePrivateKey    Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1encodePrivateKey
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1getData             Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1getData
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1fromPrivateKeyInfo  Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1fromPrivateKeyInfo
#define Java_org_openssl_jostle_util_asn1_Asn1NiJNI_ni_1fromPublicKeyInfo   Java_org_openssl_jostle_jcajce_provider_fips_Asn1FIPSJNI_ni_1fromPublicKeyInfo
/* *INDENT-ON* */

#include "asn1_ni_jni.c"
