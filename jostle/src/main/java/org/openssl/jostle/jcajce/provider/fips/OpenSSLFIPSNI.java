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

    // ------------------------------------------------------------------
    // Capability probes
    //
    // JSLFIPS serves one build against two modules that disagree about what
    // they implement (the validated 3.1.2 and a 3.5.x once certified), so the
    // registered surface has to be decided from the module that is actually
    // loaded. These are the MECHANISM only — policy lives in Java, in the
    // Prov* registrars. See the migration plan's task 7 for the scoping rule:
    // probes exist ONLY for capabilities that legitimately differ between
    // supported modules, never as a blanket wrapper over every algorithm.
    // ------------------------------------------------------------------

    /** {@link #canFetch} operation type: EVP_KEYMGMT_fetch. */
    int OP_KEYMGMT = 1;
    /** {@link #canFetch} operation type: EVP_KEYEXCH_fetch. */
    int OP_KEYEXCH = 2;
    /** {@link #canFetch} operation type: EVP_SIGNATURE_fetch. */
    int OP_SIGNATURE = 3;
    /** {@link #canFetch} operation type: EVP_ASYM_CIPHER_fetch. */
    int OP_ASYM_CIPHER = 4;
    /** {@link #canFetch} operation type: EVP_MD_fetch. */
    int OP_MD = 5;
    /** {@link #canFetch} operation type: EVP_CIPHER_fetch. */
    int OP_CIPHER = 6;
    /** {@link #canFetch} operation type: EVP_KDF_fetch. */
    int OP_KDF = 7;
    /** {@link #canFetch} operation type: EVP_MAC_fetch. */
    int OP_MAC = 8;
    /** {@link #canFetch} operation type: EVP_RAND_fetch. */
    int OP_RAND = 9;

    /**
     * Can the loaded module resolve {@code name} for {@code opType} under the
     * FIPS lib ctx's {@code fips=yes} default properties?
     *
     * <p>This is the cheap, side-effect-free probe: a fetch and an immediate
     * free, with the error queue scrubbed afterwards so a negative answer
     * leaves no trace for an unrelated call to report. It answers only "is
     * this name resolvable" — a capability that a real operation reveals but
     * a fetch does not (DSA key generation, PKCS#1 v1.5 encrypt) is NOT
     * detectable here and must be classified where it fails.
     *
     * @param opType one of the {@code OP_*} constants.
     * @param name   algorithm name to resolve.
     * @return 1 when the fetch succeeds, 0 when it does not, or a negative
     * JO_* code when the arguments are unusable ({@code JO_NAME_IS_NULL},
     * {@code JO_UNEXPECTED_STATE} for an unknown {@code opType}).
     */
    int canFetch(int opType, String name);

    /**
     * The loaded FIPS module's self-reported name and version, e.g.
     * {@code "OpenSSL FIPS Provider 3.1.2"}, or null when the provider cannot
     * be queried.
     *
     * <p><b>Diagnostics only — never a gate.</b> Keying behaviour on a version
     * string is the transcribed table java-spi.md forbids, and it is wrong on
     * its own terms: the version identifies the build, not the capability, and
     * redistributors ship their own modules. Use it in messages and in
     * {@code DumpInfo}, not in an {@code if}.
     */
    String moduleVersion();
}
