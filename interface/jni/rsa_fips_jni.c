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
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1allocateSigner               Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1allocateSigner
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1decodePrivateComponents      Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1decodePrivateComponents
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1decodePrivateComponentsCrt   Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1decodePrivateComponentsCrt
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1decodePublicComponents       Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1decodePublicComponents
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1disposeSigner                Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1disposeSigner
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1generateKeyPair              Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1generateKeyPair
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1getComponent                 Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1getComponent
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1initSign                     Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1initSign
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1initVerify                   Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1initVerify
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1sign                         Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1sign
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1update                       Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1update
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAServiceJNI_ni_1verify                       Java_org_openssl_jostle_jcajce_provider_fips_RSAServiceFIPSJNI_ni_1verify
/* *INDENT-ON* */

#include "rsa_ni_jni.c"
