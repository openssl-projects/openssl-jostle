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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.lang.ref.Reference;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * DSA Signature SPI for the standard {@code SHAxxxwithDSA} family.
 * One instance per (digest, DSA) pair; the digest name is fixed at
 * construction time.
 *
 * <p>Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this SPI instance (which
 * owns the native dsa_ctx) reachable across native calls, replacing the
 * {@code synchronized(this)} idiom used in the baseline.
 */
public class DSASignatureSpi extends SignatureSpi
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS); foreign keys translate through the
    // matching KeyFactory.
    protected final DSAServiceNI dsaServiceNI;
    protected final DSAKeyFactorySpi keyFactory;

    private final String digestName;
    private DSARef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private Object lastKey = null;


    public DSASignatureSpi(String digestName)
    {
        this(NISelector.DSAServiceNI, new DSAKeyFactorySpi(), digestName);
    }

    public DSASignatureSpi(DSAServiceNI dsaServiceNI, DSAKeyFactorySpi keyFactory, String digestName)
    {
        this.dsaServiceNI = dsaServiceNI;
        this.keyFactory = keyFactory;
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
    private JODSAPublicKey importPublic(PublicKey publicKey) throws InvalidKeyException
    {
        if (publicKey instanceof JODSAPublicKey)
        {
            // Public keys carry no secret material and may cross between the
            // Jostle providers freely (OpenSSL imports the public components
            // into this library's lib ctx); only PRIVATE keys are isolated.
            return (JODSAPublicKey) publicKey;
        }
        try
        {
            Key translated = keyFactory.engineTranslateKey(publicKey);
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
    private JODSAPrivateKey importPrivate(PrivateKey privateKey) throws InvalidKeyException
    {
        if (privateKey instanceof JODSAPrivateKey)
        {
            JODSAPrivateKey joKey = (JODSAPrivateKey) privateKey;
            if (joKey.getSpec().getSpecNI() != keyFactory.ownSpecNI())
            {
                // Keys are bound to the interface library (and OSSL_LIB_CTX)
                // that created them; JSL and JSLFIPS keys must not cross
                // implicitly.
                throw new InvalidKeyException(
                        "private key was created by a different Jostle provider; encode it with getEncoded() and decode it through this provider's KeyFactory");
            }
            return joKey;
        }
        try
        {
            Key translated = keyFactory.engineTranslateKey(privateKey);
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
        try
        {
            JODSAPublicKey key = importPublic(publicKey);
            lastKey = key;
            initVerifyInternal(key);
        }
        finally
        {
            Reference.reachabilityFence(this);
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

        try
        {
            JODSAPrivateKey key = importPrivate(privateKey);
            lastKey = key;
            initSignInternal(key);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Bind an already-imported private key for signing using the SPI's
     * current {@code randSource}. Separated from {@link #engineInitSign}
     * so {@link #reInit} can re-bind after a terminal op WITHOUT replacing
     * the caller-supplied SecureRandom (which {@code engineInitSign(key,
     * random)} would do via {@code replaceWith}).
     */
    private void initSignInternal(JODSAPrivateKey key)
    {
        ensureRef();
        dsaServiceNI.initSign(ref.getReference(), key.getSpec().getReference(),
                digestName, randSource);
    }

    /** Verify-side counterpart to {@link #initSignInternal}. */
    private void initVerifyInternal(JODSAPublicKey key)
    {
        ensureRef();
        dsaServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), digestName);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException
    {
        engineUpdate(new byte[]{b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
    {
        requireInitialised();
        try
        {
            dsaServiceNI.update(ref.getReference(), b, off, len);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException
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
            try
            {
                reInit();
            }
            finally
            {
                Reference.reachabilityFence(this);
            }
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
        requireInitialised();
        try
        {
            int code = dsaServiceNI.verify(
                    ref.getReference(),
                    sigBytes,
                    sigBytes != null ? sigBytes.length : 0,
                    randSource);
            return code == ErrorCode.JO_SUCCESS.getCode();
        }
        catch (OpenSSLException e)
        {
            // A structurally-invalid signature (unparseable DER) makes
            // OpenSSL's DSA verify return -1, surfacing as OpenSSLException
            // (a RuntimeException). The JCA contract requires an
            // improperly-encoded signature to raise SignatureException,
            // not an undeclared runtime exception.
            throw new SignatureException("unable to verify DSA signature", e);
        }
        finally
        {
            try
            {
                reInit();
            }
            finally
            {
                Reference.reachabilityFence(this);
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
            ref = new DSARef(dsaServiceNI, dsaServiceNI.allocateSigner(), "DSA");
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
     * update starts fresh against the same key. Re-binds via the
     * {@code *Internal} helpers so the caller-supplied {@code randSource}
     * survives — re-entering {@code engineInitSign(key)} here would
     * silently swap it for the project default.
     */
    private void reInit()
    {
        try
        {
            if (lastKey instanceof JODSAPublicKey)
            {
                initVerifyInternal((JODSAPublicKey) lastKey);
            }
            else if (lastKey instanceof JODSAPrivateKey)
            {
                initSignInternal((JODSAPrivateKey) lastKey);
            }
        }
        catch (Exception e)
        {
            throw new java.security.ProviderException("unable to reinitialise DSA signature engine", e);
        }
    }


    protected static class Disposer extends NativeDisposer
    {
        private final DSAServiceNI dsaServiceNI;

        Disposer(DSAServiceNI dsaServiceNI, long ref)
        {
            super(ref);
            this.dsaServiceNI = dsaServiceNI;
        }

        @Override
        protected void dispose(long reference)
        {
            dsaServiceNI.disposeSigner(reference);
        }
    }

    protected static class DSARef extends NativeReference
    {

        protected DSARef(DSAServiceNI dsaServiceNI, long reference, String name)
        {
            super(reference, name, new Disposer(dsaServiceNI, reference));
        }

    }


    // ProvDSA registers each digest variant via lambda — the inner
    // classes below give className-attribute consumers a stable Class<?>
    // per digest.

    public static class SHA1 extends DSASignatureSpi
    {
        public SHA1() { super("SHA-1"); }
    }

    public static class SHA224 extends DSASignatureSpi
    {
        public SHA224() { super("SHA-224"); }
    }

    public static class SHA256 extends DSASignatureSpi
    {
        public SHA256() { super("SHA-256"); }
    }

    public static class SHA384 extends DSASignatureSpi
    {
        public SHA384() { super("SHA-384"); }
    }

    public static class SHA512 extends DSASignatureSpi
    {
        public SHA512() { super("SHA-512"); }
    }

    public static class SHA3_224 extends DSASignatureSpi
    {
        public SHA3_224() { super("SHA3-224"); }
    }

    public static class SHA3_256 extends DSASignatureSpi
    {
        public SHA3_256() { super("SHA3-256"); }
    }

    public static class SHA3_384 extends DSASignatureSpi
    {
        public SHA3_384() { super("SHA3-384"); }
    }

    public static class SHA3_512 extends DSASignatureSpi
    {
        public SHA3_512() { super("SHA3-512"); }
    }

    /**
     * Raw DSA — "NoneWithDSA". No hashing; the caller-supplied digest is
     * buffered and signed/verified directly (DER-encoded DSA signature).
     * Required by externally-hashed DSA signing (the TLS pattern).
     */
    public static class None extends DSASignatureSpi
    {
        public None() { super("NONE"); }
    }
}
