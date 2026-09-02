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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.lang.ref.Reference;
import java.security.InvalidKeyException;
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
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS); foreign keys translate through the
    // matching KeyFactory.
    protected final ECServiceNI ecServiceNI;
    protected final ECKeyFactorySpi keyFactory;

    private final String digestName;
    private ECRef ref;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private Object lastKey = null;


    public ECDSASignatureSpi(String digestName)
    {
        this(NISelector.ECServiceNI, new ECKeyFactorySpi(), digestName);
    }

    public ECDSASignatureSpi(ECServiceNI ecServiceNI, ECKeyFactorySpi keyFactory, String digestName)
    {
        this.ecServiceNI = ecServiceNI;
        this.keyFactory = keyFactory;
        this.digestName = digestName;
    }


    // Foreign-key translation lives in ECKeyImport (shared with the
    // key-agreement SPIs); see ECKeyImport.importPublic / importPrivate.


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
        try
        {
            JOECPublicKey key = ECKeyImport.importPublic(keyFactory, publicKey);
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
            JOECPrivateKey key = ECKeyImport.importPrivate(keyFactory, privateKey);
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
            // MT-39, ruled by Megan 2026-09-02: "if BC or the JCE accept
            // zero length signatures then we should too" - and measured,
            // BOTH references THROW here, so the rule's OR clause never
            // engages for ECDSA and we throw as well.
            //
            // A zero-length signature is not a ECDSA signature that fails to
            // verify; it is structurally impossible, since the DER SEQUENCE
            // carrying (r, s) cannot be empty. Returning false said "this
            // signature did not match", a different and weaker claim. Our own
            // NONEwithECDSA path already threw, so this also removes an
            // inconsistency between two entry points of this same class.
            //
            // The null case rides the same guard - disclosed, not assumed: we
            // previously raised SignatureException here, where verify() declares
            // SignatureException and BouncyCastle raises it. (The JDK raises a
            // raw NullPointerException for DSA - its own defect, not a target.)
            if (sigBytes == null || sigBytes.length == 0)
            {
                throw new SignatureException(
                        "signature is " + (sigBytes == null ? "null" : "empty")
                                + "; a ECDSA signature cannot be");
            }

            int code = ecServiceNI.verify(
                    ref.getReference(),
                    sigBytes,
                    sigBytes != null ? sigBytes.length : 0,
                    randSource);
            return code == ErrorCode.JO_SUCCESS.getCode();
        }
        catch (OpenSSLException | IllegalArgumentException e)
        {
            // A structurally-invalid signature (unparseable DER) makes
            // OpenSSL's ECDSA verify return -1, surfacing as OpenSSLException;
            // a null / out-of-range signature surfaces as
            // IllegalArgumentException from the bridge. The JCA contract
            // requires an improperly-encoded signature to raise
            // SignatureException, not an undeclared runtime exception.
            throw new SignatureException("unable to verify ECDSA signature", e);
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
            ref = new ECRef(ecServiceNI, ecServiceNI.allocateSigner(), "ECDSA");
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
        private final ECServiceNI ecServiceNI;

        Disposer(ECServiceNI ecServiceNI, long ref)
        {
            super(ref);
            this.ecServiceNI = ecServiceNI;
        }

        @Override
        protected void dispose(long reference)
        {
            ecServiceNI.disposeSigner(reference);
        }
    }

    protected static class ECRef extends NativeReference
    {

        protected ECRef(ECServiceNI ecServiceNI, long reference, String name)
        {
            super(reference, name, new Disposer(ecServiceNI, reference));
        }

    }
}
