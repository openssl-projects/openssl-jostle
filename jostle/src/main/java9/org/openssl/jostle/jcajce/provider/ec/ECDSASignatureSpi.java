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

import java.lang.ref.Reference;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * ECDSA Signature SPI for the standard {@code SHAxxxwithECDSA} family.
 * One instance per (digest, EC) pair; the digest name is fixed at
 * construction time.
 *
 * <p>Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this SPI instance (which
 * owns the native ec_ctx) reachable across native calls, replacing the
 * {@code synchronized(this)} idiom used in the baseline.
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
        try
        {
            JOECPublicKey key = ECKeyImport.importPublic(publicKey);
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
            JOECPrivateKey key = ECKeyImport.importPrivate(privateKey);
            lastKey = key;
            initSignInternal(key);
        }
        finally
        {
            Reference.reachabilityFence(this);
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
        requireInitialised();
        try
        {
            ecServiceNI.update(ref.getReference(), b, off, len);
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
            int code = ecServiceNI.verify(
                    ref.getReference(),
                    sigBytes,
                    sigBytes != null ? sigBytes.length : 0,
                    randSource);
            return code == ErrorCode.JO_SUCCESS.getCode();
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
     * Bind an already-imported private key for signing using the SPI's
     * current {@code randSource}. Separated from {@link #engineInitSign}
     * so {@link #reInit} can re-bind after a terminal op WITHOUT replacing
     * the caller-supplied SecureRandom (which {@code engineInitSign(key,
     * random)} would do via {@code replaceWith}).
     */
    private void initSignInternal(JOECPrivateKey key)
    {
        ensureRef();
        ecServiceNI.initSign(ref.getReference(), key.getSpec().getReference(),
                digestName, randSource);
    }

    /** Verify-side counterpart to {@link #initSignInternal}. */
    private void initVerifyInternal(JOECPublicKey key)
    {
        ensureRef();
        ecServiceNI.initVerify(ref.getReference(), key.getSpec().getReference(), digestName);
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
            if (lastKey instanceof JOECPublicKey)
            {
                initVerifyInternal((JOECPublicKey) lastKey);
            }
            else if (lastKey instanceof JOECPrivateKey)
            {
                initSignInternal((JOECPrivateKey) lastKey);
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
        public SHA1() { super("SHA-1"); }
    }

    public static class SHA224 extends ECDSASignatureSpi
    {
        public SHA224() { super("SHA-224"); }
    }

    public static class SHA256 extends ECDSASignatureSpi
    {
        public SHA256() { super("SHA-256"); }
    }

    public static class SHA384 extends ECDSASignatureSpi
    {
        public SHA384() { super("SHA-384"); }
    }

    public static class SHA512 extends ECDSASignatureSpi
    {
        public SHA512() { super("SHA-512"); }
    }

    public static class SHA3_224 extends ECDSASignatureSpi
    {
        public SHA3_224() { super("SHA3-224"); }
    }

    public static class SHA3_256 extends ECDSASignatureSpi
    {
        public SHA3_256() { super("SHA3-256"); }
    }

    public static class SHA3_384 extends ECDSASignatureSpi
    {
        public SHA3_384() { super("SHA3-384"); }
    }

    public static class SHA3_512 extends ECDSASignatureSpi
    {
        public SHA3_512() { super("SHA3-512"); }
    }

    /**
     * Raw ECDSA — "NoneWithECDSA". No hashing; the caller-supplied digest is
     * buffered and signed/verified directly (DER-encoded ECDSA signature).
     * Required by TLS 1.3's externally-hashed ECDSA CertificateVerify.
     */
    public static class None extends ECDSASignatureSpi
    {
        public None() { super("NONE"); }
    }
}
