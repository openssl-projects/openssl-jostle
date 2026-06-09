/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.blockcipher;

import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Structural accessor for BouncyCastle's
 * {@code org.bouncycastle.jcajce.spec.AEADParameterSpec} without a compile-time
 * dependency on it — the same reflective-foreign-spec pattern the KDF factories
 * use for BC's {@code ScryptKeySpec}.
 *
 * <p>{@code AEADParameterSpec} extends {@link IvParameterSpec} and additionally
 * carries an AEAD tag length ({@code getMacSizeInBits()}) and associated data
 * ({@code getAssociatedData()}). Because it is an {@code IvParameterSpec}
 * subclass, a plain {@code instanceof IvParameterSpec} check in an AEAD cipher
 * SPI swallows it and silently drops both extra fields — the tag is then
 * computed without the AAD, producing a valid-looking but wrong tag (and a
 * {@code bad tag} on the decrypt side). This accessor lets the SPI recognise
 * and honour the spec instead.
 *
 * <p>Shared by the multi-release {@code BlockCipherSpi} copies (this class is
 * not version-specific), so the reflection lives in exactly one place.
 */
final class AEADParameterSpecAccessor
{
    private final byte[] iv;
    private final int macSizeInBits;
    private final byte[] associatedData;

    private AEADParameterSpecAccessor(byte[] iv, int macSizeInBits, byte[] associatedData)
    {
        this.iv = iv;
        this.macSizeInBits = macSizeInBits;
        this.associatedData = associatedData;
    }

    byte[] getIV()
    {
        return iv;
    }

    int getMacSizeInBits()
    {
        return macSizeInBits;
    }

    byte[] getAssociatedData()
    {
        return associatedData;
    }

    /**
     * True if {@code spec} is an {@link IvParameterSpec} that also exposes the
     * {@code getMacSizeInBits()} and {@code getAssociatedData()} accessors of a
     * BouncyCastle {@code AEADParameterSpec}.
     */
    static boolean matches(AlgorithmParameterSpec spec)
    {
        if (!(spec instanceof IvParameterSpec))
        {
            return false;
        }
        Class<?> cls = spec.getClass();
        return hasNoArgMethod(cls, "getMacSizeInBits") && hasNoArgMethod(cls, "getAssociatedData");
    }

    /**
     * Reflectively read the AEAD fields. {@link #matches(AlgorithmParameterSpec)}
     * must have returned true for {@code spec}. A spec that doesn't expose the
     * expected accessors (or whose return types differ) surfaces as
     * {@link InvalidAlgorithmParameterException}.
     */
    static AEADParameterSpecAccessor extract(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException
    {
        try
        {
            byte[] iv = ((IvParameterSpec) spec).getIV();
            int mac = (Integer) spec.getClass().getMethod("getMacSizeInBits").invoke(spec);
            byte[] aad = (byte[]) spec.getClass().getMethod("getAssociatedData").invoke(spec);
            return new AEADParameterSpecAccessor(iv, mac, aad);
        }
        catch (ReflectiveOperationException | ClassCastException | NullPointerException e)
        {
            throw new InvalidAlgorithmParameterException("unsupported AEAD parameter spec: " + spec, e);
        }
    }

    private static boolean hasNoArgMethod(Class<?> cls, String name)
    {
        try
        {
            cls.getMethod(name);
            return true;
        }
        catch (NoSuchMethodException e)
        {
            return false;
        }
    }
}
