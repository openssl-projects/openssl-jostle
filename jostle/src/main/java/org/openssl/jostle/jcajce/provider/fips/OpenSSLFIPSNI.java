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

import org.openssl.jostle.jcajce.provider.OpenSSLNI;

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

    // Aliases, not a second table: one C contract (JO_CAP_OP_* in
    // util/capability.h), one Java definition, on OpenSSLNI.

    /** {@link #canFetch} operation type: EVP_KEYMGMT_fetch. */
    int OP_KEYMGMT = OpenSSLNI.OP_KEYMGMT;
    /** {@link #canFetch} operation type: EVP_KEYEXCH_fetch. */
    int OP_KEYEXCH = OpenSSLNI.OP_KEYEXCH;
    /** {@link #canFetch} operation type: EVP_SIGNATURE_fetch. */
    int OP_SIGNATURE = OpenSSLNI.OP_SIGNATURE;
    /** {@link #canFetch} operation type: EVP_ASYM_CIPHER_fetch. */
    int OP_ASYM_CIPHER = OpenSSLNI.OP_ASYM_CIPHER;
    /** {@link #canFetch} operation type: EVP_MD_fetch. */
    int OP_MD = OpenSSLNI.OP_MD;
    /** {@link #canFetch} operation type: EVP_CIPHER_fetch. */
    int OP_CIPHER = OpenSSLNI.OP_CIPHER;
    /** {@link #canFetch} operation type: EVP_KDF_fetch. */
    int OP_KDF = OpenSSLNI.OP_KDF;
    /** {@link #canFetch} operation type: EVP_MAC_fetch. */
    int OP_MAC = OpenSSLNI.OP_MAC;
    /** {@link #canFetch} operation type: EVP_RAND_fetch. */
    int OP_RAND = OpenSSLNI.OP_RAND;

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

    /**
     * Names the OpenSSL provider that actually IMPLEMENTS {@code name} for
     * {@code opType} in the FIPS interface library's lib ctx - {@code "fips"}
     * for the module, {@code "default"} for mainline's built-in provider - or
     * null when the algorithm is not fetchable there at all.
     *
     * <p><b>This is the only direct evidence that an operation runs inside the
     * FIPS module.</b> Every other signal is indirect. Absence tests
     * (Triple-DES, ChaCha20, OCB) show the lib ctx carries {@code fips=yes}
     * default properties; behavioural refusals (q-less DH, SHA-1 signing,
     * DSA generation) show the module is in the path for THOSE algorithms.
     * Neither helps for a family mainline implements identically - and the
     * bundled libcrypto implements ML-KEM, ML-DSA and SLH-DSA exactly as the
     * 3.5.x module does, so for PQC there is no behaviour to tell them apart.
     *
     * <p><b>What it does NOT prove.</b> The answer describes the lib ctx
     * reachable through THIS NI - the FIPS interface library's - not the one a
     * particular algorithm SPI happens to be bound to. A single {@code *FIPSFFI}
     * class that resolved its symbols through the process-global
     * {@code loaderLookup} instead of {@link FIPSLibraryLookup} would drive the
     * BASE library while this probe still answered {@code "fips"}, because the
     * probe runs through a different, correctly-bound class. Verified by
     * deliberately reintroducing that bug: this test stayed green.
     *
     * <p>Per-family symbol binding is therefore enforced structurally instead,
     * by {@code FIPSLibraryLookupParityTest} - the invariant cannot be observed
     * behaviourally for a family mainline implements identically.
     *
     * <p>Unlike {@link #moduleVersion()} this IS a legitimate thing to assert
     * on - it reports what OpenSSL resolved, not what a build claims.
     */
    String implementingProvider(int opType, String name);
}
