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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.rand.RandSource;

/**
 * RSA Signature SPI for PKCS#1 v1.5 padding (the "SHAxxxwithRSA"
 * family). One instance per (digest, RSA) pair; the digest name
 * is fixed at construction time and propagated to the native init.
 */
public class RSASignatureSpi extends RSASignatureSpiBase
{
    private final String digestName;

    public RSASignatureSpi(String digestName)
    {
        this.digestName = digestName;
    }

    @Override
    protected void nativeInitSign(long ref, long keyRef, RandSource rnd)
    {
        rsaServiceNI.initSign(ref, keyRef,
                digestName,
                RSAServiceNI.PADDING_PKCS1,
                null,           // no MGF1 — ignored by PKCS#1 v1.5 anyway
                0,              // no salt — ignored
                rnd);
    }

    @Override
    protected void nativeInitVerify(long ref, long keyRef)
    {
        rsaServiceNI.initVerify(ref, keyRef,
                digestName,
                RSAServiceNI.PADDING_PKCS1,
                null,
                0);
    }


    // ProvRSA registers each digest variant via lambda — the inner
    // classes below give checkstyle / className-attribute consumers
    // a stable Class<?> per digest.

    public static class MD5 extends RSASignatureSpi
    {
        public MD5()
        {
            super("MD5");
        }
    }

    public static class SHA1 extends RSASignatureSpi
    {
        public SHA1()
        {
            super("SHA-1");
        }
    }

    public static class SHA224 extends RSASignatureSpi
    {
        public SHA224()
        {
            super("SHA-224");
        }
    }

    public static class SHA256 extends RSASignatureSpi
    {
        public SHA256()
        {
            super("SHA-256");
        }
    }

    public static class SHA384 extends RSASignatureSpi
    {
        public SHA384()
        {
            super("SHA-384");
        }
    }

    public static class SHA512 extends RSASignatureSpi
    {
        public SHA512()
        {
            super("SHA-512");
        }
    }

    public static class SHA3_224 extends RSASignatureSpi
    {
        public SHA3_224()
        {
            super("SHA3-224");
        }
    }

    public static class SHA3_256 extends RSASignatureSpi
    {
        public SHA3_256()
        {
            super("SHA3-256");
        }
    }

    public static class SHA3_384 extends RSASignatureSpi
    {
        public SHA3_384()
        {
            super("SHA3-384");
        }
    }

    public static class SHA3_512 extends RSASignatureSpi
    {
        public SHA3_512()
        {
            super("SHA3-512");
        }
    }

    /**
     * Raw PKCS#1 v1.5 — "NoneWithRSA". The engine performs no hashing; the
     * caller-supplied bytes (typically a pre-formed DigestInfo) are buffered
     * and signed/verified with PKCS#1 v1.5 block-type-1 padding directly.
     * Required by TLS 1.3's externally-hashed CertificateVerify path
     * (BouncyCastle's {@code JcaTlsRSASigner.getRawSigner()}).
     */
    public static class None extends RSASignatureSpi
    {
        public None()
        {
            super("NONE");
        }

        @Override
        protected void nativeInitSign(long ref, long keyRef, RandSource rnd)
        {
            rsaServiceNI.initSign(ref, keyRef,
                    "NONE",
                    RSAServiceNI.PADDING_PKCS1_NONE,
                    null,
                    0,
                    rnd);
        }

        @Override
        protected void nativeInitVerify(long ref, long keyRef)
        {
            rsaServiceNI.initVerify(ref, keyRef,
                    "NONE",
                    RSAServiceNI.PADDING_PKCS1_NONE,
                    null,
                    0);
        }
    }
}
