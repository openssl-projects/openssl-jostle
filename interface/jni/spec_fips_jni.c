//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for SpecFIPSJNI: the base glue re-included
// under the FIPS class's symbols (see md_fips_jni.c for the pattern
// rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes spec_ni_jni.c
// itself); the base interface_jni compiles spec_ni_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_spec_SpecJNI_ni_1dispose   Java_org_openssl_jostle_jcajce_provider_fips_SpecFIPSJNI_ni_1dispose
#define Java_org_openssl_jostle_jcajce_spec_SpecJNI_ni_1allocate  Java_org_openssl_jostle_jcajce_provider_fips_SpecFIPSJNI_ni_1allocate
#define Java_org_openssl_jostle_jcajce_spec_SpecJNI_ni_1getName   Java_org_openssl_jostle_jcajce_provider_fips_SpecFIPSJNI_ni_1getName
#define Java_org_openssl_jostle_jcajce_spec_SpecJNI_ni_1encap     Java_org_openssl_jostle_jcajce_provider_fips_SpecFIPSJNI_ni_1encap
#define Java_org_openssl_jostle_jcajce_spec_SpecJNI_ni_1decap     Java_org_openssl_jostle_jcajce_provider_fips_SpecFIPSJNI_ni_1decap
/* *INDENT-ON* */

#include "spec_ni_jni.c"
