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

/**
 * One Cipher transformation under survey, with the shape facts a fault needs.
 *
 * <p>Keyed on the TRANSFORMATION, never on the registered name. AES registers
 * one Cipher name and serves roughly eighteen distinct transformations whose
 * refusals differ from each other; a survey keyed on registered names would
 * measure one of them and report on all.
 */
public final class CipherCell
{
    public final String transformation;
    public final String keyAlgorithm;
    public final int keyBytes;
    /** 0 when the mode takes no IV. */
    public final int ivBytes;
    public final boolean aead;
    /** Tag length in bits for an AEAD mode, else 0. */
    public final int tagBits;
    public final boolean wrap;
    /** True when a padding scheme makes arbitrary input lengths legal. */
    public final boolean padded;
    public final int blockBytes;
    /**
     * Plaintext length for this cell's baseline and faults.
     *
     * <p><b>Deliberately independent of {@link #blockBytes}.</b> The first
     * version of this class had none and sized the plaintext as
     * {@code blockBytes * 4}, which made {@code blockBytes} govern two
     * dimensions at once: whether the mode requires aligned input, AND how much
     * input every fault gets. Stream modes carry {@code blockBytes == 1} to say
     * "no alignment requirement" and silently received a FOUR BYTE plaintext,
     * so their output-capacity cells measured a buffering corner rather than
     * the capacity rule, and reported a BouncyCastle divergence that a direct
     * probe at 64 bytes could not reproduce. Exactly the one-knob-two-dimensions
     * trap recorded in testing.md from the MT-3 arc.
     */
    public final int plaintextBytes;

    public CipherCell(String transformation, String keyAlgorithm, int keyBytes, int ivBytes,
                      boolean aead, int tagBits, boolean wrap, boolean padded, int blockBytes)
    {
        this(transformation, keyAlgorithm, keyBytes, ivBytes, aead, tagBits, wrap, padded, blockBytes, 64);
    }

    public CipherCell(String transformation, String keyAlgorithm, int keyBytes, int ivBytes,
                      boolean aead, int tagBits, boolean wrap, boolean padded, int blockBytes,
                      int plaintextBytes)
    {
        this.plaintextBytes = plaintextBytes;
        this.transformation = transformation;
        this.keyAlgorithm = keyAlgorithm;
        this.keyBytes = keyBytes;
        this.ivBytes = ivBytes;
        this.aead = aead;
        this.tagBits = tagBits;
        this.wrap = wrap;
        this.padded = padded;
        this.blockBytes = blockBytes;
    }

    /** A block cipher mode whose input length must be a multiple of the block. */
    public boolean requiresAlignedInput()
    {
        return !padded && !aead && !wrap && blockBytes > 1;
    }

    @Override
    public String toString()
    {
        return transformation + "/" + (keyBytes * 8);
    }
}
