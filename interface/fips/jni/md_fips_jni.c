//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for MDServiceFIPSJNI.
//
// JNI binds native methods by class-name-derived symbol, so the FIPS library
// must export Java_*_fips_MDServiceFIPSJNI_* names distinct from the base
// library's Java_*_md_MDServiceJNI_* names. Rather than duplicating the
// wrapper bodies, the base glue is re-included with each exported function
// renamed to the FIPS class's symbol: the #defines below rewrite both the
// generated-header declarations and the definitions in md_jni.c at
// preprocessing time. The wrapper logic therefore has exactly one source of
// truth; this file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni (which excludes md_jni.c itself);
// the base interface_jni compiles md_jni.c directly.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1allocateDigest      Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1allocateDigest
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1copyDigest          Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1copyDigest
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1updateByte          Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1updateByte
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1updateBytes         Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1updateBytes
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1dispose             Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1dispose
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1getDigestOutputLen  Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1getDigestOutputLen
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1digest              Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1digest
#define Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1reset               Java_org_openssl_jostle_jcajce_provider_fips_MDServiceFIPSJNI_ni_1reset
/* *INDENT-ON* */

#include "md_jni.c"
