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
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1allocateCipher            Java_org_openssl_jostle_jcajce_provider_fips_RSAOAEPCipherFIPSJNI_ni_1allocateCipher
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1disposeCipher             Java_org_openssl_jostle_jcajce_provider_fips_RSAOAEPCipherFIPSJNI_ni_1disposeCipher
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1doFinal                   Java_org_openssl_jostle_jcajce_provider_fips_RSAOAEPCipherFIPSJNI_ni_1doFinal
#define Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1init                      Java_org_openssl_jostle_jcajce_provider_fips_RSAOAEPCipherFIPSJNI_ni_1init
/* *INDENT-ON* */

#include "rsa_oaep_ni_jni.c"
