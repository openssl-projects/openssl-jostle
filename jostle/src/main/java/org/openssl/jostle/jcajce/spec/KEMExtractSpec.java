/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;

import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Initialises a KEM {@code KeyGenerator} to extract, with a private key, the key a {@link KEMGenerateSpec}
 * produced. The size, KDF and {@code otherInfo} must match the sender's; the defaults are the same, X9.44 KDF3
 * with SHA-256, a 256-bit key and empty {@code otherInfo}. See {@link KEMGenerateSpec} for the rules.
 */
public class KEMExtractSpec implements AlgorithmParameterSpec
{
    private final PrivateKey privateKey;
    private final String algorithmName;
    private final int keySizeInBits;
    private final byte[] encapsulation;
    private final byte[] kdfAlgorithm;
    private final byte[] otherInfo;

    /** A spec with the default KDF and empty {@code otherInfo}. */
    public KEMExtractSpec(PrivateKey publicKey, String algorithmName, int keySize, byte[] encapsulation)
    {
        this(publicKey, algorithmName, keySize, encapsulation, KdfAlgorithmIdentifiers.defaultKdf(), new byte[0]);
    }

    private KEMExtractSpec(PrivateKey privateKey, String algorithmName, int keySize, byte[] encapsulation,
                           byte[] kdfAlgorithm, byte[] otherInfo)
    {
        this.privateKey = privateKey;
        this.algorithmName = algorithmName;
        this.keySizeInBits = keySize;
        this.encapsulation = Arrays.clone(encapsulation);
        this.kdfAlgorithm = Arrays.clone(kdfAlgorithm);
        this.otherInfo = Arrays.clone(otherInfo);
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getKeySizeInBits()
    {
        return keySizeInBits;
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }

    /**
     * @return a copy of the KDF {@code AlgorithmIdentifier}'s DER encoding, or null when
     * {@link Builder#withNoKdf()} was used.
     */
    public byte[] getKdfAlgorithm()
    {
        return Arrays.clone(kdfAlgorithm);
    }

    /** @return a copy of the {@code otherInfo} fed to the KDF; never null. */
    public byte[] getOtherInfo()
    {
        return Arrays.clone(otherInfo);
    }

    /** @return a builder with a 256-bit key size, the default KDF and empty {@code otherInfo}. */
    public static Builder builder()
    {
        return new Builder(null, null, 256, null, KdfAlgorithmIdentifiers.defaultKdf(), new byte[0]);
    }

    public static class Builder
    {
        private final PrivateKey privateKey;
        private final String algorithmName;
        private final int keySizeInBits;
        private final byte[] encapsulation;
        private final byte[] kdfAlgorithm;
        private final byte[] otherInfo;

        private Builder(PrivateKey privateKey, String algorithmName, int keysize, byte[] encapsulation,
                        byte[] kdfAlgorithm, byte[] otherInfo)
        {
            this.privateKey = privateKey;
            this.algorithmName = algorithmName;
            this.keySizeInBits = keysize;
            this.encapsulation = encapsulation;
            this.kdfAlgorithm = kdfAlgorithm;
            this.otherInfo = otherInfo;
        }

        public Builder withPrivate(PrivateKey privateKey)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulation, kdfAlgorithm, otherInfo);
        }

        public Builder withAlgorithmName(String algorithmName)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulation, kdfAlgorithm, otherInfo);
        }

        public Builder withKeySizeInBits(int keysize)
        {
            return new Builder(privateKey, algorithmName, keysize, encapsulation, kdfAlgorithm, otherInfo);
        }

        public Builder withEncapsulatedKey(byte[] encapsulatedKey)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulatedKey, kdfAlgorithm, otherInfo);
        }

        /** As {@link KEMGenerateSpec.Builder#withKdfAlgorithm(byte[])}. */
        public Builder withKdfAlgorithm(byte[] derAlgorithmIdentifier)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulation,
                    KdfAlgorithmIdentifiers.checked(derAlgorithmIdentifier), otherInfo);
        }

        /** As {@link KEMGenerateSpec.Builder#withKdfAlgorithm(ASN1ObjectIdentifier, ASN1ObjectIdentifier)}. */
        public Builder withKdfAlgorithm(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier digest)
        {
            return withKdfAlgorithm(KdfAlgorithmIdentifiers.of(kdf, digest));
        }

        /** Use the shared secret itself as the key; no KDF is applied. */
        public Builder withNoKdf()
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulation, null, otherInfo);
        }

        /** The {@code otherInfo} the KDF takes; ignored when there is no KDF. */
        public Builder withOtherInfo(byte[] otherInfo)
        {
            return new Builder(privateKey, algorithmName, keySizeInBits, encapsulation, kdfAlgorithm,
                    otherInfo == null ? new byte[0] : Arrays.clone(otherInfo));
        }

        public KEMExtractSpec build()
        {
            return new KEMExtractSpec(privateKey, algorithmName, keySizeInBits, encapsulation, kdfAlgorithm,
                    otherInfo);
        }
    }
}
