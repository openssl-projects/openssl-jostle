/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

/**
 * AEAD parameters: nonce, MAC/tag length, and optional associated data.
 * Extends {@link IvParameterSpec} so an AEAD cipher SPI can still resolve the
 * nonce via {@link #getIV()}; use {@link #getNonce()} for the same value
 * under its AEAD name.
 */
public class AEADParameterSpec extends IvParameterSpec
{
    private final int macSizeInBits;
    private final byte[] associatedData;

    public AEADParameterSpec(byte[] nonce, int macSizeInBits)
    {
        this(nonce, macSizeInBits, null);
    }

    public AEADParameterSpec(byte[] nonce, int macSizeInBits, byte[] associatedData)
    {
        super(nonce);
        if (macSizeInBits < 32 || macSizeInBits > 128 || (macSizeInBits & 7) != 0)
        {
            throw new IllegalArgumentException(
                    "AEAD tag length must be 32 to 128 bits and a multiple of 8: " + macSizeInBits);
        }
        this.macSizeInBits = macSizeInBits;
        this.associatedData = Arrays.clone(associatedData);
    }

    public int getMacSizeInBits()
    {
        return macSizeInBits;
    }

    /** @return a copy of the associated data, or null if none was supplied. */
    public byte[] getAssociatedData()
    {
        return Arrays.clone(associatedData);
    }

    /** @return the nonce; same value as {@link #getIV()}. */
    public byte[] getNonce()
    {
        return getIV();
    }
}
