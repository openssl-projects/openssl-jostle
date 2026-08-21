/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

/**
 * JNI implementation of {@link OpenSSLFIPSNI}, backed by the FIPS interface
 * library (libinterface_fips_jni). This class deliberately lives at a
 * distinct fully-qualified name from the non-FIPS OpenSSLJNI: JNI binds
 * native methods by class-name-derived symbol, so the FIPS library exports
 * Java_org_openssl_jostle_jcajce_provider_fips_OpenSSLFIPSJNI_* symbols that
 * cannot collide with the base interface library's exports when both are
 * loaded in one JVM.
 */
class OpenSSLFIPSJNI implements OpenSSLFIPSNI
{
    @Override
    public native int setOSSLFIPSModule(String moduleDir, String providerName, String configPath);

    @Override
    public native String getOSSLErrors();

    @Override
    public native int canFetch(int opType, String name);

    @Override
    public native String moduleVersion();
}
