//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for RandServiceFIPSJNI: the base glue
// re-included under the FIPS class's symbols (see md_fips_jni.c for the
// pattern rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes rand_jni.c itself);
// the base interface_jni compiles rand_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1createContext      Java_org_openssl_jostle_jcajce_provider_fips_RandServiceFIPSJNI_ni_1createContext
#define Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1disposeContext     Java_org_openssl_jostle_jcajce_provider_fips_RandServiceFIPSJNI_ni_1disposeContext
#define Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1contextRandomBytes Java_org_openssl_jostle_jcajce_provider_fips_RandServiceFIPSJNI_ni_1contextRandomBytes
#define Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1contextReseed      Java_org_openssl_jostle_jcajce_provider_fips_RandServiceFIPSJNI_ni_1contextReseed
#define Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1drbgStrength       Java_org_openssl_jostle_jcajce_provider_fips_RandServiceFIPSJNI_ni_1drbgStrength
/* *INDENT-ON* */

#include "rand_jni.c"
