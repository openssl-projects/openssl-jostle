/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;

/**
 * A {@link KeyStore.LoadStoreParameter} for the Jostle BCFKS KeyStore, beside
 * {@link PKCS12LoadStoreParameter}. Ours only -- no BouncyCastle type appears
 * here, and {@code BcFKSKeyStoreSpi} refuses any other {@code
 * LoadStoreParameter} implementation typed, including BC's own {@code
 * BCFKSLoadStoreParameter}; a standalone Jostle parameter for a standalone
 * Jostle implementation.
 *
 * <p>Immutable: every field is set once, in the {@link Builder}, and read
 * back only through getters. Password-based protection ({@code char[]} or a
 * {@link KeyStore.ProtectionParameter}) and signature-based integrity (a
 * signing {@link PrivateKey} on write, a verifying {@link PublicKey} or a
 * {@link ChainValidator} on read) are mutually exclusive per instance -- the
 * constructor used decides which.
 */
public final class BCFKSLoadStoreParameter
    implements KeyStore.LoadStoreParameter
{
    public enum EncryptionAlgorithm
    {
        AES256_CCM,
        AES256_KWP
    }

    public enum MacAlgorithm
    {
        HmacSHA512,
        HmacSHA3_512
    }

    public enum SignatureAlgorithm
    {
        SHA512withRSA,
        SHA512withECDSA,
        SHA512withDSA,
        SHA3_512withRSA,
        SHA3_512withECDSA,
        SHA3_512withDSA
    }

    /** Validates a certificate chain found embedded in a signature-checked store. */
    public interface ChainValidator
    {
        /**
         * @param chain the chain to validate, end-entity at position 0.
         * @return {@code true} if the chain is trusted, {@code false} otherwise.
         */
        boolean isValid(Certificate[] chain);
    }

    /** Marker for {@link PBKDF2Config} / {@link ScryptConfig} -- ours only, never BC's {@code PBKDFConfig}. */
    public interface PBKDFConfig
    {
    }

    /** PBKDF2 configuration for deriving the store's encryption and integrity keys. */
    public static final class PBKDF2Config
        implements PBKDFConfig
    {
        public enum PRF
        {
            SHA512,
            SHA3_512
        }

        public static final class Builder
        {
            private int iterationCount = 51200;
            private int saltLength = 64;
            private PRF prf = PRF.SHA512;

            public Builder withIterationCount(int iterationCount)
            {
                if (iterationCount < 1)
                {
                    throw new IllegalArgumentException("iterationCount must be at least 1");
                }
                this.iterationCount = iterationCount;
                return this;
            }

            public Builder withSaltLength(int saltLength)
            {
                if (saltLength < 1)
                {
                    throw new IllegalArgumentException("saltLength must be at least 1");
                }
                this.saltLength = saltLength;
                return this;
            }

            public Builder withPRF(PRF prf)
            {
                if (prf == null)
                {
                    throw new IllegalArgumentException("prf must not be null");
                }
                this.prf = prf;
                return this;
            }

            public PBKDF2Config build()
            {
                return new PBKDF2Config(this);
            }
        }

        private final int iterationCount;
        private final int saltLength;
        private final PRF prf;

        private PBKDF2Config(Builder builder)
        {
            this.iterationCount = builder.iterationCount;
            this.saltLength = builder.saltLength;
            this.prf = builder.prf;
        }

        public int getIterationCount()
        {
            return iterationCount;
        }

        public int getSaltLength()
        {
            return saltLength;
        }

        public PRF getPrf()
        {
            return prf;
        }
    }

    /** scrypt configuration for deriving the store's encryption and integrity keys, JSL only. */
    public static final class ScryptConfig
        implements PBKDFConfig
    {
        public static final class Builder
        {
            private final int costParameter;
            private final int blockSize;
            private final int parallelizationParameter;
            private int saltLength = 16;

            public Builder(int costParameter, int blockSize, int parallelizationParameter)
            {
                if (costParameter <= 1 || (costParameter & (costParameter - 1)) != 0)
                {
                    throw new IllegalArgumentException("costParameter must be > 1 and a power of 2");
                }
                if (blockSize < 1)
                {
                    throw new IllegalArgumentException("blockSize must be at least 1");
                }
                if (parallelizationParameter < 1)
                {
                    throw new IllegalArgumentException("parallelizationParameter must be at least 1");
                }
                this.costParameter = costParameter;
                this.blockSize = blockSize;
                this.parallelizationParameter = parallelizationParameter;
            }

            public Builder withSaltLength(int saltLength)
            {
                if (saltLength < 1)
                {
                    throw new IllegalArgumentException("saltLength must be at least 1");
                }
                this.saltLength = saltLength;
                return this;
            }

            public ScryptConfig build()
            {
                return new ScryptConfig(this);
            }
        }

        private final int costParameter;
        private final int blockSize;
        private final int parallelizationParameter;
        private final int saltLength;

        private ScryptConfig(Builder builder)
        {
            this.costParameter = builder.costParameter;
            this.blockSize = builder.blockSize;
            this.parallelizationParameter = builder.parallelizationParameter;
            this.saltLength = builder.saltLength;
        }

        public int getCostParameter()
        {
            return costParameter;
        }

        public int getBlockSize()
        {
            return blockSize;
        }

        public int getParallelizationParameter()
        {
            return parallelizationParameter;
        }

        public int getSaltLength()
        {
            return saltLength;
        }
    }

    public static final class Builder
    {
        private final OutputStream outputStream;
        private final InputStream inputStream;
        private final KeyStore.ProtectionParameter protectionParameter;
        private final PrivateKey signingKey;
        private final PublicKey verificationKey;
        private final ChainValidator chainValidator;

        private EncryptionAlgorithm storeEncryptionAlgorithm = EncryptionAlgorithm.AES256_CCM;
        private MacAlgorithm storeMacAlgorithm = MacAlgorithm.HmacSHA512;
        private PBKDFConfig storePBKDFConfig;
        private Certificate[] certificates;
        private SignatureAlgorithm storeSignatureAlgorithm;

        /** Store to an OutputStream, password-protected. */
        public Builder(OutputStream outputStream, char[] password)
        {
            this(outputStream, new KeyStore.PasswordProtection(password));
        }

        /** Store to an OutputStream, protected per {@code protectionParameter}. */
        public Builder(OutputStream outputStream, KeyStore.ProtectionParameter protectionParameter)
        {
            if (outputStream == null)
            {
                throw new IllegalArgumentException("outputStream must not be null");
            }
            if (protectionParameter == null)
            {
                throw new IllegalArgumentException("protectionParameter must not be null");
            }
            this.outputStream = outputStream;
            this.inputStream = null;
            this.protectionParameter = protectionParameter;
            this.signingKey = null;
            this.verificationKey = null;
            this.chainValidator = null;
        }

        /** Store to an OutputStream, integrity-protected by a signature under {@code signingKey}. */
        public Builder(OutputStream outputStream, PrivateKey signingKey)
        {
            if (outputStream == null)
            {
                throw new IllegalArgumentException("outputStream must not be null");
            }
            if (signingKey == null)
            {
                throw new IllegalArgumentException("signingKey must not be null");
            }
            this.outputStream = outputStream;
            this.inputStream = null;
            this.protectionParameter = null;
            this.signingKey = signingKey;
            this.verificationKey = null;
            this.chainValidator = null;
        }

        /** Load from an InputStream, password-protected. */
        public Builder(InputStream inputStream, char[] password)
        {
            this(inputStream, new KeyStore.PasswordProtection(password));
        }

        /** Load from an InputStream, protected per {@code protectionParameter}. */
        public Builder(InputStream inputStream, KeyStore.ProtectionParameter protectionParameter)
        {
            if (inputStream == null)
            {
                throw new IllegalArgumentException("inputStream must not be null");
            }
            if (protectionParameter == null)
            {
                throw new IllegalArgumentException("protectionParameter must not be null");
            }
            this.outputStream = null;
            this.inputStream = inputStream;
            this.protectionParameter = protectionParameter;
            this.signingKey = null;
            this.verificationKey = null;
            this.chainValidator = null;
        }

        /** Load from an InputStream, integrity-verified against {@code verificationKey}. */
        public Builder(InputStream inputStream, PublicKey verificationKey)
        {
            if (inputStream == null)
            {
                throw new IllegalArgumentException("inputStream must not be null");
            }
            if (verificationKey == null)
            {
                throw new IllegalArgumentException("verificationKey must not be null");
            }
            this.outputStream = null;
            this.inputStream = inputStream;
            this.protectionParameter = null;
            this.signingKey = null;
            this.verificationKey = verificationKey;
            this.chainValidator = null;
        }

        /** Load from an InputStream, integrity-verified against the store's own embedded certificate chain. */
        public Builder(InputStream inputStream, ChainValidator chainValidator)
        {
            if (inputStream == null)
            {
                throw new IllegalArgumentException("inputStream must not be null");
            }
            if (chainValidator == null)
            {
                throw new IllegalArgumentException("chainValidator must not be null");
            }
            this.outputStream = null;
            this.inputStream = inputStream;
            this.protectionParameter = null;
            this.signingKey = null;
            this.verificationKey = null;
            this.chainValidator = chainValidator;
        }

        public Builder withStoreEncryptionAlgorithm(EncryptionAlgorithm storeEncryptionAlgorithm)
        {
            if (storeEncryptionAlgorithm == null)
            {
                throw new IllegalArgumentException("storeEncryptionAlgorithm must not be null");
            }
            this.storeEncryptionAlgorithm = storeEncryptionAlgorithm;
            return this;
        }

        public Builder withStoreMacAlgorithm(MacAlgorithm storeMacAlgorithm)
        {
            if (storeMacAlgorithm == null)
            {
                throw new IllegalArgumentException("storeMacAlgorithm must not be null");
            }
            this.storeMacAlgorithm = storeMacAlgorithm;
            return this;
        }

        public Builder withStorePBKDFConfig(PBKDFConfig storePBKDFConfig)
        {
            if (storePBKDFConfig == null)
            {
                throw new IllegalArgumentException("storePBKDFConfig must not be null");
            }
            this.storePBKDFConfig = storePBKDFConfig;
            return this;
        }

        /** A valid certificate chain, certs[0] the end-entity matching the signing key. Defensively copied. */
        public Builder withCertificates(Certificate[] certificates)
        {
            if (certificates == null)
            {
                throw new IllegalArgumentException("certificates must not be null");
            }
            this.certificates = Arrays.copyOf(certificates, certificates.length);
            return this;
        }

        public Builder withStoreSignatureAlgorithm(SignatureAlgorithm storeSignatureAlgorithm)
        {
            if (storeSignatureAlgorithm == null)
            {
                throw new IllegalArgumentException("storeSignatureAlgorithm must not be null");
            }
            this.storeSignatureAlgorithm = storeSignatureAlgorithm;
            return this;
        }

        public BCFKSLoadStoreParameter build()
        {
            return new BCFKSLoadStoreParameter(this);
        }
    }

    private final OutputStream outputStream;
    private final InputStream inputStream;
    private final KeyStore.ProtectionParameter protectionParameter;
    private final PrivateKey signingKey;
    private final PublicKey verificationKey;
    private final ChainValidator chainValidator;
    private final EncryptionAlgorithm storeEncryptionAlgorithm;
    private final MacAlgorithm storeMacAlgorithm;
    private final PBKDFConfig storePBKDFConfig;
    private final Certificate[] certificates;
    private final SignatureAlgorithm storeSignatureAlgorithm;

    private BCFKSLoadStoreParameter(Builder builder)
    {
        this.outputStream = builder.outputStream;
        this.inputStream = builder.inputStream;
        this.protectionParameter = builder.protectionParameter;
        this.signingKey = builder.signingKey;
        this.verificationKey = builder.verificationKey;
        this.chainValidator = builder.chainValidator;
        this.storeEncryptionAlgorithm = builder.storeEncryptionAlgorithm;
        this.storeMacAlgorithm = builder.storeMacAlgorithm;
        this.storePBKDFConfig = builder.storePBKDFConfig;
        this.certificates = builder.certificates;
        this.storeSignatureAlgorithm = builder.storeSignatureAlgorithm;
    }

    public OutputStream getOutputStream()
    {
        return outputStream;
    }

    public InputStream getInputStream()
    {
        return inputStream;
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }

    public PrivateKey getStoreSigningKey()
    {
        return signingKey;
    }

    public PublicKey getStoreVerificationKey()
    {
        return verificationKey;
    }

    public ChainValidator getChainValidator()
    {
        return chainValidator;
    }

    public EncryptionAlgorithm getStoreEncryptionAlgorithm()
    {
        return storeEncryptionAlgorithm;
    }

    public MacAlgorithm getStoreMacAlgorithm()
    {
        return storeMacAlgorithm;
    }

    /** {@code null} when the caller named none -- the SPI's own default then applies. */
    public PBKDFConfig getStorePBKDFConfig()
    {
        return storePBKDFConfig;
    }

    /** {@code null} when none were given; otherwise a defensive copy. */
    public Certificate[] getStoreCertificates()
    {
        return certificates == null ? null : Arrays.copyOf(certificates, certificates.length);
    }

    public SignatureAlgorithm getStoreSignatureAlgorithm()
    {
        return storeSignatureAlgorithm;
    }
}
