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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * ECDSA Signature SPI for the standard {@code SHAxxxwithECDSA} family.
 * One instance per (digest, EC) pair; the digest name is fixed at
 * construction time. The native side runs the digest streamed through
 * {@code EVP_DigestSignUpdate} / {@code EVP_DigestVerifyUpdate} and
 * finalises with {@code EVP_DigestSign/VerifyFinal}, producing /
 * accepting DER-encoded {@code SEQUENCE \{INTEGER r, INTEGER s\}}
 * (per RFC 5480 §2.2).
 *
 * <p>Mirrors the structure of {@code RSASignatureSpiBase}:
 * {@code synchronized(this)} keeps this SPI reachable across native
 * calls (Java 8 baseline; the java9 override would use
 * {@link java.lang.ref.Reference#reachabilityFence}); a
 * {@code requireInitialised()} guard makes pre-init misuse surface
 * as {@link IllegalStateException} instead of NPE; the {@code lastKey}
 * field pins the {@code PKEYKeySpec} so its native handle stays alive
 * across every native call; {@code reInit} restores key state after
 * a terminal sign/verify so the SPI is reusable without re-init.
 */
public class ECDSASignatureSpi extends SignatureSpi
{
    protected static final ECServiceNI ecServiceNI = NISelector.ECServiceNI;

    private final String digestName;
    private ECRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private Object lastKey = null;


    public ECDSASignatureSpi(String digestName)
    {
        this.digestName = digestName;
    }


    // Foreign-key translation lives in ECKeyImport (shared with the
    // key-agreement SPIs); see ECKeyImport.importPublic / importPrivate.


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
        synchronized (this)
        {
            JOECPublicKey key = ECKeyImport.importPublic(publicKey);
            lastKey = key;

            ensureRef();
            ecServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), digestName);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
        engineInitSign(privateKey, CryptoServicesRegistrar.getSecureRandom());
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException
    {
        this.randSource = DefaultRandSource.replaceWith(this.randSource, secureRandom);

        synchronized (this)
        {
            JOECPrivateKey key = ECKeyImport.importPrivate(privateKey);
            lastKey = key;

            ensureRef();
            ecServiceNI.initSign(ref.getReference(), key.getSpec().getReference(),
                    digestName, randSource);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException
    {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
    {
        synchronized (this)
        {
            requireInitialised();
            ecServiceNI.update(ref.getReference(), b, off, len);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        synchronized (this)
        {
            requireInitialised();
            try
            {
                int upperBound = ecServiceNI.sign(ref.getReference(), null, 0, randSource);
                byte[] sig = new byte[upperBound];
                int actualLen = ecServiceNI.sign(ref.getReference(), sig, 0, randSource);
                if (actualLen == sig.length)
                {
                    return sig;
                }
                // ECDSA DER-encoded signatures vary in length per call
                // (each integer can be 1 byte shorter when the high bit
                // is unset). Trim to the actual length the second call
                // wrote.
                byte[] trimmed = new byte[actualLen];
                System.arraycopy(sig, 0, trimmed, 0, actualLen);
                return trimmed;
            }
            finally
            {
                reInit();
            }
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
        synchronized (this)
        {
            requireInitialised();
            try
            {
                // randSource is required even on verify — OpenSSL's EC
                // implementation uses RAND for point-blinding inside
                // EVP_DigestVerifyFinal as a side-channel mitigation.
                int code = ecServiceNI.verify(
                        ref.getReference(),
                        sigBytes,
                        sigBytes != null ? sigBytes.length : 0,
                        randSource);
                return code == ErrorCode.JO_SUCCESS.getCode();
            }
            finally
            {
                reInit();
            }
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException();
    }


    private void ensureRef()
    {
        if (ref == null)
        {
            ref = new ECRef(ecServiceNI.allocateSigner(), "ECDSA");
        }
    }

    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("signature not initialised");
        }
    }

    /**
     * Re-initialise after a sign or verify so the next streaming
     * update starts fresh against the same key. Mirrors the pattern
     * in {@code RSASignatureSpiBase}.
     */
    private void reInit()
    {
        try
        {
            if (lastKey instanceof ECPublicKey)
            {
                engineInitVerify((PublicKey) lastKey);
            }
            else if (lastKey instanceof ECPrivateKey)
            {
                engineInitSign((PrivateKey) lastKey);
            }
        }
        catch (Exception e)
        {
            throw new java.security.ProviderException("unable to reinitialise ECDSA signature engine", e);
        }
    }


    protected static class Disposer extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            NISelector.ECServiceNI.disposeSigner(reference);
        }
    }

    protected static class ECRef extends NativeReference
    {
        protected ECRef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }


    // ProvEC registers each digest variant via lambda — the inner
    // classes below give className-attribute consumers a stable Class<?>
    // per digest.

    public static class SHA1 extends ECDSASignatureSpi
    {
        public SHA1()
        {
            super("SHA-1");
        }
    }

    public static class SHA224 extends ECDSASignatureSpi
    {
        public SHA224()
        {
            super("SHA-224");
        }
    }

    public static class SHA256 extends ECDSASignatureSpi
    {
        public SHA256()
        {
            super("SHA-256");
        }
    }

    public static class SHA384 extends ECDSASignatureSpi
    {
        public SHA384()
        {
            super("SHA-384");
        }
    }

    public static class SHA512 extends ECDSASignatureSpi
    {
        public SHA512()
        {
            super("SHA-512");
        }
    }

    public static class SHA3_224 extends ECDSASignatureSpi
    {
        public SHA3_224()
        {
            super("SHA3-224");
        }
    }

    public static class SHA3_256 extends ECDSASignatureSpi
    {
        public SHA3_256()
        {
            super("SHA3-256");
        }
    }

    public static class SHA3_384 extends ECDSASignatureSpi
    {
        public SHA3_384()
        {
            super("SHA3-384");
        }
    }

    public static class SHA3_512 extends ECDSASignatureSpi
    {
        public SHA3_512()
        {
            super("SHA3-512");
        }
    }

    /**
     * Raw ECDSA — "NoneWithECDSA". The engine performs no hashing; the
     * caller-supplied bytes (an already-computed digest) are buffered and
     * signed/verified directly, producing/consuming a DER-encoded ECDSA
     * signature. Required by TLS 1.3's externally-hashed ECDSA
     * CertificateVerify (BouncyCastle's JcaTlsECDSA13Signer).
     */
    public static class None extends ECDSASignatureSpi
    {
        public None()
        {
            super("NONE");
        }
    }
}
