/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rand;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;

/**
 * SecureRandom algorithms registered by the Jostle provider.
 * <p>
 * Each constant binds a JCA SecureRandom name to an OpenSSL DRBG mechanism
 * (the {@code EVP_RAND} name) and a variant — a cipher SN for CTR-DRBG, or a
 * digest SN for HASH-DRBG / HMAC-DRBG. {@code DRBG} (aliased to {@code DEFAULT})
 * additionally honors the {@code securerandom.drbg.config} security property so
 * the mechanism/algorithm can be selected the JDK way; the mechanism-named
 * constants are fixed and ignore the property.
 * </p>
 */
public enum RandAlgorithm
{
    /**
     * Configurable default DRBG service (CTR-DRBG / AES-256-CTR unless overridden
     * by {@code securerandom.drbg.config}). Aliased to {@code DEFAULT}.
     */
    DRBG("DRBG", "CTR-DRBG", "AES-256-CTR", true, true),

    CTR_DRBG("CTR-DRBG", "CTR-DRBG", "AES-256-CTR", true, false),
    CTR_DRBG_AES128("CTR-DRBG-AES128", "CTR-DRBG", "AES-128-CTR", true, false),
    CTR_DRBG_AES192("CTR-DRBG-AES192", "CTR-DRBG", "AES-192-CTR", true, false),
    CTR_DRBG_AES256("CTR-DRBG-AES256", "CTR-DRBG", "AES-256-CTR", true, false),

    HASH_DRBG("HASH-DRBG", "HASH-DRBG", "SHA2-256", false, false),
    HASH_DRBG_SHA1("HASH-DRBG-SHA1", "HASH-DRBG", "SHA1", false, false),
    HASH_DRBG_SHA224("HASH-DRBG-SHA224", "HASH-DRBG", "SHA2-224", false, false),
    HASH_DRBG_SHA256("HASH-DRBG-SHA256", "HASH-DRBG", "SHA2-256", false, false),
    HASH_DRBG_SHA384("HASH-DRBG-SHA384", "HASH-DRBG", "SHA2-384", false, false),
    HASH_DRBG_SHA512("HASH-DRBG-SHA512", "HASH-DRBG", "SHA2-512", false, false),

    HMAC_DRBG("HMAC-DRBG", "HMAC-DRBG", "SHA2-256", false, false),
    HMAC_DRBG_SHA1("HMAC-DRBG-SHA1", "HMAC-DRBG", "SHA1", false, false),
    HMAC_DRBG_SHA224("HMAC-DRBG-SHA224", "HMAC-DRBG", "SHA2-224", false, false),
    HMAC_DRBG_SHA256("HMAC-DRBG-SHA256", "HMAC-DRBG", "SHA2-256", false, false),
    HMAC_DRBG_SHA384("HMAC-DRBG-SHA384", "HMAC-DRBG", "SHA2-384", false, false),
    HMAC_DRBG_SHA512("HMAC-DRBG-SHA512", "HMAC-DRBG", "SHA2-512", false, false);

    private final String jcaName;
    private final String mechanism;
    private final String variant;
    private final boolean useDerivationFunction;
    private final boolean honorsConfig;

    /**
     * Memoizes the OpenSSL-reported strength per mechanism/variant so each
     * distinct variant is probed at most once. The probe is keyless metadata —
     * no DRBG is instantiated and no entropy is drawn — mirroring the
     * {@link NativeLengthCache} usage for cipher/MAC lengths elsewhere.
     */
    private static final NativeLengthCache<String> STRENGTH_CACHE = new NativeLengthCache<String>();

    RandAlgorithm(String jcaName, String mechanism, String variant,
                  boolean useDerivationFunction, boolean honorsConfig)
    {
        if (jcaName == null || mechanism == null || variant == null)
        {
            throw new NullPointerException("jcaName, mechanism and variant cannot be null");
        }

        this.jcaName = jcaName;
        this.mechanism = mechanism;
        this.variant = variant;
        this.useDerivationFunction = useDerivationFunction;
        this.honorsConfig = honorsConfig;
    }

    /**
     * Returns the JCA algorithm name used during provider registration.
     *
     * @return the JCA SecureRandom algorithm name
     */
    public String getJcaName()
    {
        return jcaName;
    }

    /**
     * Returns the OpenSSL DRBG mechanism (the {@code EVP_RAND} name).
     *
     * @return one of {@code CTR-DRBG}, {@code HASH-DRBG}, {@code HMAC-DRBG}
     */
    public String getMechanism()
    {
        return mechanism;
    }

    /**
     * Returns the variant selector — a cipher SN for CTR-DRBG, a digest SN for
     * HASH-DRBG / HMAC-DRBG.
     *
     * @return the OpenSSL cipher or digest SN
     */
    public String getVariant()
    {
        return variant;
    }

    /**
     * Returns whether the CTR-DRBG derivation function is requested. Only
     * meaningful for the CTR mechanism; ignored otherwise.
     *
     * @return {@code true} if the derivation function should be used
     */
    public boolean usesDerivationFunction()
    {
        return useDerivationFunction;
    }

    /**
     * Returns whether this algorithm consults the
     * {@code securerandom.drbg.config} security property to select its
     * mechanism/variant.
     *
     * @return {@code true} only for the {@code DRBG}/{@code DEFAULT} service
     */
    public boolean honorsConfig()
    {
        return honorsConfig;
    }

    /**
     * Returns the maximum security strength advertised by this algorithm's
     * default variant.
     *
     * @return strength in bits
     */
    public int getMaxStrength()
    {
        return maxStrengthFor(variant);
    }

    /**
     * Returns the security strength (bits) for a DRBG variant, as reported by
     * OpenSSL — CTR-DRBG from the cipher key length, HASH/HMAC-DRBG from the
     * digest. The value is queried from the native layer (no DRBG instantiated)
     * and memoized, so nothing is transcribed here that could drift from native
     * truth. Strength depends only on the variant, so a digest is probed via
     * HASH-DRBG even when the caller will use HMAC-DRBG — both report the same.
     *
     * @param variant the cipher SN (CTR) or digest SN (HASH/HMAC)
     * @return strength in bits
     */
    static int maxStrengthFor(String variant)
    {
        String mechanism = variant != null && variant.startsWith("AES") ? "CTR-DRBG" : "HASH-DRBG";
        String key = mechanism + "/" + variant;

        int cached = STRENGTH_CACHE.get(key);
        if (cached != NativeLengthCache.UNKNOWN)
        {
            return cached;
        }

        int strength = NISelector.RandServiceNI.drbgStrength(mechanism, variant);
        STRENGTH_CACHE.cache(key, strength);
        return strength;
    }
}
