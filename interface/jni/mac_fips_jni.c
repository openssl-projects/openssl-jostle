//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for MacServiceFIPSJNI: the base glue
// re-included under the FIPS class's symbols (see md_fips_jni.c for the
// pattern rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes mac_jni.c itself);
// the base interface_jni compiles mac_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1allocateMac    Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1allocateMac
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1init           Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1init
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateByte     Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1updateByte
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateBytes    Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1updateBytes
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1doFinal        Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1doFinal
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1getMacLength   Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1getMacLength
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1macLengthMeta  Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1macLengthMeta
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1reset          Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1reset
#define Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1dispose        Java_org_openssl_jostle_jcajce_provider_fips_MacServiceFIPSJNI_ni_1dispose
/* *INDENT-ON* */

#include "mac_jni.c"
