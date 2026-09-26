/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kts;

import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Arrays;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;

/**
 * How a KEM {@code KeyGenerator} turns the shared secret into the key the caller asked for, decided once at init
 * from the spec's key size, KDF and {@code otherInfo}. Shared by the ML-KEM and hybrid generators.
 * <p>
 * With a KDF, the key is the KDF's output over the shared secret and {@code otherInfo}, of the requested size.
 * Without one, it is the shared secret, cut to a shorter size as BouncyCastle does; a larger size is refused at
 * init. The shared secret's length is asked of the library that holds the key, never written down.
 */
public final class KemKeyDerivation
{
    private final Provider ownProvider;
    private final KtsKdf.Kind kind;
    private final String digestName;
    private final byte[] otherInfo;
    private final int keyBytes;
    private final int secretBytes;

    private KemKeyDerivation(Provider ownProvider, KtsKdf.Kind kind, String digestName, byte[] otherInfo,
                             int keyBytes, int secretBytes)
    {
        this.ownProvider = ownProvider;
        this.kind = kind;
        this.digestName = digestName;
        this.otherInfo = otherInfo;
        this.keyBytes = keyBytes;
        this.secretBytes = secretBytes;
    }

    /**
     * Decide the derivation for a key of {@code keySizeInBits} from a KEM key held in {@code key}'s library.
     *
     * @param kdfAlgorithm the spec's KDF {@code AlgorithmIdentifier} encoding, or null for no KDF.
     * @param ownProvider  the generator's provider instance; the KDF's primitives come from it.
     */
    public static KemKeyDerivation plan(PKEYKeySpec key, int keySizeInBits, byte[] kdfAlgorithm, byte[] otherInfo,
                                        Provider ownProvider, RandSource randSource)
        throws InvalidAlgorithmParameterException
    {
        if (keySizeInBits <= 0)
        {
            throw new InvalidAlgorithmParameterException("KEM key size in bits must be positive: " + keySizeInBits);
        }
        // Whole bytes, rounding up, as BouncyCastle does.
        int keyBytes = (keySizeInBits + 7) / 8;
        int secretBytes = key.getSpecNI().sharedSecretLength(key.getReference(), key.getType(), randSource);

        if (kdfAlgorithm == null)
        {
            if (keyBytes > secretBytes)
            {
                throw new InvalidAlgorithmParameterException("KEM key size " + keySizeInBits
                        + " bits is larger than the " + secretBytes * 8 + "-bit shared secret, and no KDF is set");
            }
            return new KemKeyDerivation(null, null, null, null, keyBytes, secretBytes);
        }

        KtsKdf.Resolved resolved = KtsKdf.resolveForKem(kdfAlgorithm);
        if (ownProvider == null)
        {
            throw new InvalidAlgorithmParameterException("this KeyGenerator was constructed outside any "
                    + "provider, so it has none to derive the key through; obtain it from a Jostle provider");
        }
        try
        {
            KtsKdf.requireAvailable(ownProvider, resolved.kind, resolved.digestName);
            int max = KtsKdf.maxOutputBytes(ownProvider, resolved.kind);
            if (max >= 0 && keyBytes > max)
            {
                throw new InvalidAlgorithmParameterException("KEM key size " + keySizeInBits + " bits is larger "
                        + "than the " + max * 8 + " bits " + resolved.digestName + " derives here");
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
        return new KemKeyDerivation(ownProvider, resolved.kind, resolved.digestName, Arrays.clone(otherInfo),
                keyBytes, secretBytes);
    }

    /** @return the shared secret's length in bytes, for sizing the encapsulation's output. */
    public int secretBytes()
    {
        return secretBytes;
    }

    /**
     * The key bytes from the shared secret {@code z}. The caller clears both {@code z} and the result.
     */
    public byte[] keyFrom(byte[] z)
    {
        if (z.length != secretBytes)
        {
            throw new IllegalStateException("shared secret length mismatch");
        }
        if (kind == null)
        {
            return java.util.Arrays.copyOf(z, keyBytes);
        }
        try
        {
            return KtsKdf.derive(ownProvider, kind, digestName, z, otherInfo, keyBytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            // Checked at init; a provider that stopped serving the primitive since is a provider failure.
            throw new ProviderException(e.getMessage(), e);
        }
    }
}
