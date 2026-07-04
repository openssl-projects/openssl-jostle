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
 * Native interface for initialising the FIPS interface library.
 *
 * <p>The FIPS provider runs against its own interface library
 * (libinterface_fips_jni / libinterface_fips_ffi): a separate compile of the
 * same native util layer whose own copy of the process globals holds a
 * FIPS-only OSSL_LIB_CTX, so the FIPS and non-FIPS Jostle providers can
 * coexist in one JVM.
 *
 * <p>The OpenSSL FIPS module itself is NOT loaded with System.load: libcrypto
 * locates and dlopens it (running the integrity-MAC check and self-tests)
 * when the native side loads the config. All file-path handling (deriving the
 * module directory, provider name, and defaulted config path) happens on the
 * Java side before this call.
 */
public interface OpenSSLFIPSNI
{
    /**
     * Initialise the FIPS interface library's lib ctx: load the FIPS module
     * (plus the base provider) into a new OSSL_LIB_CTX and pin it to
     * fips=yes default properties. One-shot per JVM.
     *
     * @param moduleDir    directory containing the FIPS provider module; used
     *                     as the OpenSSL module search path.
     * @param providerName provider name OpenSSL maps to the module file
     *                     (e.g. "fips" for fips.dylib / fips.so / fips.dll).
     * @param configPath   path to the fipsinstall-generated config
     *                     (fipsmodule.cnf) carrying the module-mac.
     * @return JO_SUCCESS or a negative JO_* code (see ErrorCode).
     */
    int setOSSLFIPSModule(String moduleDir, String providerName, String configPath);

    /**
     * Drain and return the OpenSSL error queue of the FIPS interface library.
     */
    String getOSSLErrors();
}
