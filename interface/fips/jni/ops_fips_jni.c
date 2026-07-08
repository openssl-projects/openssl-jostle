//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//
// FIPS interface library glue for OperationsTestFIPSJNI.
//
// JNI binds native methods by class-name-derived symbol, so the FIPS library
// must export Java_*_fips_OperationsTestFIPSJNI_* names distinct from the base
// library's Java_*_ops_OperationsTestJNI_* names. Rather than duplicating the
// wrapper bodies, the base glue is re-included with each exported function
// renamed to the FIPS class's symbol: the #defines below rewrite both the
// generated-header declarations and the definitions in jni/ops.c at
// preprocessing time. The wrapper logic therefore has exactly one source of
// truth; this file must only ever contain renames.
//
// Like jni/ops.c itself, everything here is #ifdef JOSTLE_OPS - a shipped
// (non-JOSTLE_OPS_TEST) FIPS build exports no operations-test symbols at all.
//
#define Java_org_openssl_jostle_util_ops_OperationsTestJNI_setOpsTestFlag  Java_org_openssl_jostle_jcajce_provider_fips_OperationsTestFIPSJNI_setOpsTestFlag
#define Java_org_openssl_jostle_util_ops_OperationsTestJNI_op_1getEntropy  Java_org_openssl_jostle_jcajce_provider_fips_OperationsTestFIPSJNI_op_1getEntropy
#include "ops.c"
