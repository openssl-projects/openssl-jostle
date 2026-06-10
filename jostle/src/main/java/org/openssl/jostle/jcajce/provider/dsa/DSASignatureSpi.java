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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

/**
 * DSA Signature SPI for the standard {@code SHAxxxwithDSA} family.
 * One instance per (digest, DSA) pair; the digest name is fixed at
 * construction time. The native side runs the digest streamed through
 * {@code EVP_DigestSignUpdate} / {@code EVP_DigestVerifyUpdate} and
 * finalises with {@code EVP_DigestSign/VerifyFinal}, producing /
 * accepting DER-encoded {@code SEQUENCE \{INTEGER r, INTEGER s\}}
 * (per RFC 3279 §2.2.2).
 *
 * <p>Mirrors the structure of {@code ECDSASignatureSpi}:
 * {@code synchronized(this)} keeps this SPI reachable across native
 * calls (Java 8 baseline); a {@code requireInitialised()} guard makes
 * pre-init misuse surface as {@link IllegalStateException} instead of
 * NPE; the {@code lastKey} field pins the {@code PKEYKeySpec} so its
 * native handle stays alive across every native call; {@code reInit}
 * restores key state after a terminal sign/verify so the SPI is
 * reusable without re-init.
 */
public class DSASignatureSpi extends SignatureSpi
{
    protected static final DSAServiceNI dsaServiceNI = NISelector.DSAServiceNI;

    private final String digestName;
    private DSARef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private Object lastKey = null;


    public DSASignatureSpi(String digestName)
    {
        this.digestName = digestName;
    }


    /**
     * Coerce an arbitrary public key to a JSL DSA public key. JSL keys
     * are used directly; foreign DSA keys (e.g. a {@code sun.*} key from
     * a JDK-parsed certificate, as the CMS/PKIX verifiers hand us) are
     * re-imported through {@link DSAKeyFactorySpi#engineTranslateKey} so
     * external callers interoperate without having to pre-convert keys.
     * Anything that isn't DSA surfaces as {@link InvalidKeyException}.
     */
    private static JODSAPublicKey importPublic(PublicKey publicKey) throws InvalidKeyException
    {
        if (publicKey instanceof JODSAPublicKey)
        {
            return (JODSAPublicKey) publicKey;
        }
        try
        {
            Key translated = new DSAKeyFactorySpi().engineTranslateKey(publicKey);
            if (translated instanceof JODSAPublicKey)
            {
                return (JODSAPublicKey) translated;
            }
        }
        catch (InvalidKeyException e)
        {
            // Wrong-algorithm or unparseable key — fall through to the canonical message.
        }
        throw new InvalidKeyException("expected a DSAPublicKey from the Jostle provider");
    }

    /** Private-key counterpart to {@link #importPublic}. */
    private static JODSAPrivateKey importPrivate(PrivateKey privateKey) throws InvalidKeyException
    {
        if (privateKey instanceof JODSAPrivateKey)
        {
            return (JODSAPrivateKey) privateKey;
        }
        try
        {
            Key translated = new DSAKeyFactorySpi().engineTranslateKey(privateKey);
            if (translated instanceof JODSAPrivateKey)
            {
                return (JODSAPrivateKey) translated;
            }
        }
        catch (InvalidKeyException e)
        {
            // Wrong-algorithm or unparseable key — fall through to the canonical message.
        }
        throw new InvalidKeyException("expected a DSAPrivateKey from the Jostle provider");
    }


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
        synchronized (this)
        {
            JODSAPublicKey key = importPublic(publicKey);
            lastKey = key;

            ensureRef();
            dsaServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), digestName);
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
            JODSAPrivateKey key = importPrivate(privateKey);
            lastKey = key;

            ensureRef();
            dsaServiceNI.initSign(ref.getReference(), key.getSpec().getReference(),
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
            dsaServiceNI.update(ref.getReference(), b, off, len);
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
                int upperBound = dsaServiceNI.sign(ref.getReference(), null, 0, randSource);
                byte[] sig = new byte[upperBound];
                int actualLen = dsaServiceNI.sign(ref.getReference(), sig, 0, randSource);
                if (actualLen == sig.length)
                {
                    return sig;
                }
                // DSA DER-encoded signatures vary in length per call
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
                // randSource is bound on the verify path for parity
                // with the EC surface (see DSAServiceNI.ni_verify).
                int code = dsaServiceNI.verify(
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
            ref = new DSARef(dsaServiceNI.allocateSigner(), "DSA");
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
     * in {@code ECDSASignatureSpi}.
     */
    private void reInit()
    {
        try
        {
            if (lastKey instanceof DSAPublicKey)
            {
                engineInitVerify((PublicKey) lastKey);
            }
            else if (lastKey instanceof DSAPrivateKey)
            {
                engineInitSign((PrivateKey) lastKey);
            }
        }
        catch (Exception e)
        {
            throw new java.security.ProviderException("unable to reinitialise DSA signature engine", e);
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
            NISelector.DSAServiceNI.disposeSigner(reference);
        }
    }

    protected static class DSARef extends NativeReference
    {
        protected DSARef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }


    // ProvDSA registers each digest variant via lambda — the inner
    // classes below give className-attribute consumers a stable Class<?>
    // per digest.

    public static class SHA1 extends DSASignatureSpi
    {
        public SHA1()
        {
            super("SHA-1");
        }
    }

    public static class SHA224 extends DSASignatureSpi
    {
        public SHA224()
        {
            super("SHA-224");
        }
    }

    public static class SHA256 extends DSASignatureSpi
    {
        public SHA256()
        {
            super("SHA-256");
        }
    }

    public static class SHA384 extends DSASignatureSpi
    {
        public SHA384()
        {
            super("SHA-384");
        }
    }

    public static class SHA512 extends DSASignatureSpi
    {
        public SHA512()
        {
            super("SHA-512");
        }
    }

    public static class SHA3_224 extends DSASignatureSpi
    {
        public SHA3_224()
        {
            super("SHA3-224");
        }
    }

    public static class SHA3_256 extends DSASignatureSpi
    {
        public SHA3_256()
        {
            super("SHA3-256");
        }
    }

    public static class SHA3_384 extends DSASignatureSpi
    {
        public SHA3_384()
        {
            super("SHA3-384");
        }
    }

    public static class SHA3_512 extends DSASignatureSpi
    {
        public SHA3_512()
        {
            super("SHA3-512");
        }
    }

    /**
     * Raw DSA — "NoneWithDSA". The engine performs no hashing; the
     * caller-supplied bytes (an already-computed digest) are buffered and
     * signed/verified directly, producing/consuming a DER-encoded DSA
     * signature. Required by externally-hashed signing (the TLS pattern;
     * BouncyCastle's JcaTlsDSASigner.generateRawSignature).
     */
    public static class None extends DSASignatureSpi
    {
        public None()
        {
            super("NONE");
        }
    }
}
