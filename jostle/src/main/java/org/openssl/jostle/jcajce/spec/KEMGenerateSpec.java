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

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Initialises a KEM {@code KeyGenerator} to encapsulate to a public key. The generated key is derived from the
 * shared secret through a KDF, X9.44 KDF3 with SHA-256 unless another is named, over the shared secret and the
 * optional {@code otherInfo}, so any key size is available and both sides derive the same key. With
 * {@link Builder#withNoKdf()} the key is the shared secret itself, cut to a shorter size, and a size larger than
 * the secret is refused at init. The defaults and the accepted KDFs are BouncyCastle's; for the hybrid TLS groups,
 * which BouncyCastle does not serve, applying the same default is Jostle's own choice.
 */
public class KEMGenerateSpec implements AlgorithmParameterSpec
{
    private final PublicKey publicKey;
    private final String algorithmName;
    private final int keySizeInBits;
    private final byte[] kdfAlgorithm;
    private final byte[] otherInfo;

    private KEMGenerateSpec(PublicKey publicKey, String algorithmName, int keySizeInBits, byte[] kdfAlgorithm,
                            byte[] otherInfo)
    {
        this.publicKey = publicKey;
        this.algorithmName = algorithmName;
        this.keySizeInBits = keySizeInBits;
        this.kdfAlgorithm = kdfAlgorithm;
        this.otherInfo = otherInfo;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getKeySizeInBits()
    {
        return keySizeInBits;
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
        return new Builder(null, null, 256, KdfAlgorithmIdentifiers.defaultKdf(), new byte[0]);
    }

    public static class Builder
    {
        private final PublicKey publicKey;
        private final String algorithmName;
        private final int keySizeInBits;
        private final byte[] kdfAlgorithm;
        private final byte[] otherInfo;

        private Builder(PublicKey publicKey, String algorithmName, int keysize, byte[] kdfAlgorithm,
                        byte[] otherInfo)
        {
            this.publicKey = publicKey;
            this.algorithmName = algorithmName;
            this.keySizeInBits = keysize;
            this.kdfAlgorithm = kdfAlgorithm;
            this.otherInfo = otherInfo;
        }

        public Builder withPublicKey(PublicKey publicKey)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits, kdfAlgorithm, otherInfo);
        }

        public Builder withAlgorithmName(String algorithmName)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits, kdfAlgorithm, otherInfo);
        }

        public Builder withKeySizeInBits(int keysize)
        {
            return new Builder(publicKey, algorithmName, keysize, kdfAlgorithm, otherInfo);
        }

        /**
         * Name the KDF by its {@code AlgorithmIdentifier}'s DER encoding: X9.44 KDF2 or KDF3 over SHA-256,
         * SHA-512, SHAKE128 or SHAKE256, HKDF with SHA-256, SHA-384 or SHA-512 (RFC 8619), or SHAKE256 alone.
         */
        public Builder withKdfAlgorithm(byte[] derAlgorithmIdentifier)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits,
                    KdfAlgorithmIdentifiers.checked(derAlgorithmIdentifier), otherInfo);
        }

        /**
         * Name the KDF by its OID and, for X9.44 KDF2/KDF3, the digest's OID; {@code digest} is null for the
         * HKDF OIDs and for SHAKE256 alone.
         */
        public Builder withKdfAlgorithm(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier digest)
        {
            return withKdfAlgorithm(KdfAlgorithmIdentifiers.of(kdf, digest));
        }

        /** Use the shared secret itself as the key; no KDF is applied. */
        public Builder withNoKdf()
        {
            return new Builder(publicKey, algorithmName, keySizeInBits, null, otherInfo);
        }

        /** The {@code otherInfo} the KDF takes; ignored when there is no KDF. */
        public Builder withOtherInfo(byte[] otherInfo)
        {
            return new Builder(publicKey, algorithmName, keySizeInBits, kdfAlgorithm,
                    otherInfo == null ? new byte[0] : Arrays.clone(otherInfo));
        }

        public KEMGenerateSpec build()
        {
            return new KEMGenerateSpec(publicKey, algorithmName, keySizeInBits, Arrays.clone(kdfAlgorithm),
                    Arrays.clone(otherInfo));
        }
    }
}
