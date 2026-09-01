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

package org.openssl.jostle.test.parity;

import java.security.spec.AlgorithmParameterSpec;

/**
 * One Signature transformation under survey, with the shape facts a fault needs.
 *
 * <h2>Why the table is keyed on the SPI CLASS, not on the registered name</h2>
 *
 * <p>JSL registers seventy Signature names across EIGHT SPI classes, and a
 * negative path is a property of the class, not of the name: every one of the
 * ten {@code *withDSA} names is the same {@code DSASignatureSpi} refusing in the
 * same place. A survey with seventy rows would spend sixty-two of them
 * re-measuring code it had already measured, and would still be blind to any
 * class it happened to miss. {@link SignatureNegativePathSurveyTest} therefore
 * carries representative cells and a CENSUS that maps all seventy names back to
 * their class and fails if any class has no cell - the coverage claim comes from
 * the census, never from the length of this table.
 *
 * <h2>No BouncyCastle name map</h2>
 *
 * <p>There is deliberately none. Measured 2026-09-01: BouncyCastle's
 * {@code Signature.getInstance} resolves 63 of our 70 names verbatim, so a
 * transcribed alias table would be an identity function with seven holes -
 * pure drift risk for no information. The seven it cannot resolve
 * ({@code Ed25519ctx}, {@code Ed25519ph}, {@code Ed448ph}, {@code SLH-DSA-NONE},
 * {@code SLH-DSA-PURE} and the two {@code DET-} forms) are surveyed anyway and
 * land as {@code BC_ABSENT} rows, so the universe is never quietly shrunk to the
 * part BouncyCastle happens to answer for.
 */
public final class SignatureCell
{
    /** The JCE transformation, spelled the same way for both providers. */
    public final String transformation;
    /** Simple name of the JSL SPI class this cell is the representative of. */
    public final String spiClass;
    /** KeyPairGenerator algorithm. */
    public final String kpgAlgorithm;
    /** Key size for the int overload, or 0 when {@link #kpgSpec} or a bare generate applies. */
    public final int kpgKeySize;
    /** Parameter spec for the AlgorithmParameterSpec overload, or null. */
    public final AlgorithmParameterSpec kpgSpec;
    /** KeyFactory algorithm BouncyCastle decodes our encodings through. */
    public final String bcKeyFactory;
    /**
     * Digest to pre-hash the message with, or null for a streaming transformation.
     *
     * <p>The {@code NONEwith*} paths take an already-hashed input of exactly the
     * right length; feeding them a raw message measures a length refusal rather
     * than the fault under test.
     */
    public final String prehashDigest;
    /**
     * Parameters both providers are initialised with, or null.
     *
     * <p>Non-null for PSS for a documented reason: this project defaults PSS to
     * SHA-256/MGF1-SHA-256 where BouncyCastle defaults to SHA-1, so
     * default-against-default cross-verification FAILS BY DESIGN (java-spi.md,
     * "Modern defaults policy"). Measured here on the first run - both
     * directions returned false - which is the bidirectional baseline earning
     * its place: it caught a real, documented divergence before a single fault
     * had been applied.
     */
    public final AlgorithmParameterSpec params;

    public SignatureCell(String transformation, String spiClass, String kpgAlgorithm,
                         int kpgKeySize, AlgorithmParameterSpec kpgSpec, String bcKeyFactory,
                         String prehashDigest, AlgorithmParameterSpec params)
    {
        this.transformation = transformation;
        this.spiClass = spiClass;
        this.kpgAlgorithm = kpgAlgorithm;
        this.kpgKeySize = kpgKeySize;
        this.kpgSpec = kpgSpec;
        this.bcKeyFactory = bcKeyFactory;
        this.prehashDigest = prehashDigest;
        this.params = params;
    }

    /** Cache key: cells sharing a key algorithm and sizing share one generated pair. */
    public String keyCacheKey()
    {
        return kpgAlgorithm + "/" + kpgKeySize + "/" + (kpgSpec == null ? "-" : kpgSpec.toString());
    }

    @Override
    public String toString()
    {
        return transformation;
    }
}
