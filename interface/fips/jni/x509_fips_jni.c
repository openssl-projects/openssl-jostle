//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS interface library glue for X509ServiceFIPSJNI: the base glue
// re-included under the FIPS class's symbols (see md_fips_jni.c for the
// pattern rationale). This file must only ever contain renames.
//
// Compiled ONLY into interface_fips_jni, over fips/util/x509.c, whose lib ctx
// accessor is spelled apart so a FIPS parse cannot resolve through the base
// lib ctx. Without this file the FIPS provider drove the BASE library.
//

/* *INDENT-OFF* */
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1allocate         Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1allocate
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1allocateCrl      Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1allocateCrl
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlEntries       Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1crlEntries
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlEntriesLen    Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1crlEntriesLen
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlExtensions    Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1crlExtensions
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlExtensionsLen Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1crlExtensionsLen
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlFields        Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1crlFields
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlFieldsLen     Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1crlFieldsLen
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1dispose          Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1dispose
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1disposeCrl       Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1disposeCrl
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1extensions       Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1extensions
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1extensionsLen    Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1extensionsLen
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1fields           Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1fields
#define Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1fieldsLen        Java_org_openssl_jostle_jcajce_provider_fips_X509ServiceFIPSJNI_ni_1fieldsLen
/* *INDENT-ON* */

#include "x509_ni_jni.c"
