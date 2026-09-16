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
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;
import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameters for the RSA-KEM and ML-KEM KTS (key-transport) ciphers: the
 * AES key-wrap algorithm name, the KEK size, an optional {@code otherInfo}
 * fed to the KDF, and the KDF's own {@code AlgorithmIdentifier} (X9.44
 * KDF2/KDF3, or RFC 8619 HKDF), carried as its DER encoding so this class has
 * no dependency on any ASN.1 object-identifier library.
 *
 * <p>Mirrors the construction shape of BouncyCastle's own
 * {@code org.bouncycastle.jcajce.spec.KTSParameterSpec} so callers building one
 * from a BC {@code AlgorithmIdentifier} port by replacing that argument with
 * its {@code getEncoded()}. {@code org.openssl.jostle.jcajce.provider.rsa.RSAKEMCipherSpi}
 * and {@code org.openssl.jostle.jcajce.provider.mlkem.MLKEMKTSCipherSpi} accept
 * only this class.
 */
public class KTSParameterSpec
    implements AlgorithmParameterSpec
{
    /**
     * Ceiling on the KDF {@code AlgorithmIdentifier} DER. An
     * {@code AlgorithmIdentifier} naming a KDF and a digest is under 40 bytes;
     * 256 leaves room for parameters this class does not yet interpret without
     * being open-ended.
     */
    private static final int MAX_KDF_ALGORITHM_BYTES = 256;

    private final String keyAlgorithmName;
    private final int keySize;
    private final byte[] otherInfo;
    private final byte[] kdfAlgorithm;

    private KTSParameterSpec(String keyAlgorithmName, int keySize, byte[] otherInfo, byte[] kdfAlgorithm)
    {
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySize = keySize;
        this.otherInfo = otherInfo;
        this.kdfAlgorithm = kdfAlgorithm;
    }

    /**
     * @return the AES key-wrap algorithm name (e.g. {@code "AESWRAP"} for
     * RFC 3394 KW, {@code "AES-KWP"} for RFC 5649 KWP).
     */
    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }

    /** @return the KEK size in bits. */
    public int getKeySize()
    {
        return keySize;
    }

    /** @return a copy of the {@code otherInfo} fed to the KDF; never null. */
    public byte[] getOtherInfo()
    {
        return Arrays.clone(otherInfo);
    }

    /**
     * @return a copy of the KDF {@code AlgorithmIdentifier}'s DER encoding, or
     * null when {@link Builder#withNoKdf()} was used (the shared secret is the
     * KEK directly).
     */
    public byte[] getKdfAlgorithm()
    {
        return Arrays.clone(kdfAlgorithm);
    }

    public static final class Builder
    {
        /**
         * KDF3 (X9.44 concatenation KDF) with SHA-256 — the default when
         * neither {@link #withKdfAlgorithm(byte[])} nor {@link #withNoKdf()} is
         * called. Matches BouncyCastle's default.
         */
        private static final byte[] DEFAULT_KDF_ALGORITHM = Der.sequence(
                Der.objectIdentifier(X9ObjectIdentifiers.id_kdf_kdf3.getId()),
                Der.sequence(Der.objectIdentifier(NISTObjectIdentifiers.id_sha256.getId())));

        private final String algorithmName;
        private final int keySizeInBits;
        private final byte[] otherInfo;
        private byte[] kdfAlgorithm = DEFAULT_KDF_ALGORITHM;

        public Builder(String algorithmName, int keySizeInBits)
        {
            this(algorithmName, keySizeInBits, new byte[0]);
        }

        public Builder(String algorithmName, int keySizeInBits, byte[] otherInfo)
        {
            if (algorithmName == null)
            {
                throw new IllegalArgumentException("algorithm name is null");
            }
            if (keySizeInBits <= 0)
            {
                throw new IllegalArgumentException("key size must be positive: " + keySizeInBits);
            }
            this.algorithmName = algorithmName;
            this.keySizeInBits = keySizeInBits;
            this.otherInfo = Arrays.clone(otherInfo == null ? new byte[0] : otherInfo);
        }

        /**
         * Set the KDF's {@code AlgorithmIdentifier} from its DER encoding.
         *
         * @param derAlgorithmIdentifier the encoded {@code AlgorithmIdentifier};
         *                               never null; use {@link #withNoKdf()}
         *                               for no KDF.
         * @return this builder.
         */
        public Builder withKdfAlgorithm(byte[] derAlgorithmIdentifier)
        {
            if (derAlgorithmIdentifier == null)
            {
                throw new NullPointerException("derAlgorithmIdentifier is null");
            }
            if (derAlgorithmIdentifier.length > MAX_KDF_ALGORITHM_BYTES)
            {
                throw new IllegalArgumentException(
                        "KDF AlgorithmIdentifier exceeds " + MAX_KDF_ALGORITHM_BYTES + " bytes: "
                                + derAlgorithmIdentifier.length);
            }
            this.kdfAlgorithm = Arrays.clone(derAlgorithmIdentifier);
            return this;
        }

        /**
         * Set the KDF's {@code AlgorithmIdentifier} from its OID and, for
         * X9.44 KDF2/KDF3, the digest's OID. {@code digest} is null for the
         * RFC 8619 HKDF OIDs, which name their digest in the KDF OID itself and
         * carry no parameters.
         *
         * @return this builder.
         */
        public Builder withKdfAlgorithm(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier digest)
        {
            if (kdf == null)
            {
                throw new NullPointerException("kdf is null");
            }
            byte[] der = (digest == null)
                    ? Der.sequence(Der.objectIdentifier(kdf.getId()))
                    : Der.sequence(Der.objectIdentifier(kdf.getId()),
                            Der.sequence(Der.objectIdentifier(digest.getId())));
            return withKdfAlgorithm(der);
        }

        /** Use the shared secret directly as the KEK; no KDF is applied. */
        public Builder withNoKdf()
        {
            this.kdfAlgorithm = null;
            return this;
        }

        public KTSParameterSpec build()
        {
            return new KTSParameterSpec(algorithmName, keySizeInBits, otherInfo, kdfAlgorithm);
        }
    }
}
