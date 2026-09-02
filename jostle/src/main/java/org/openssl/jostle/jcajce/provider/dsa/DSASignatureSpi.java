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

import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;

import java.security.*;

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
            // MT-14: instance-checked. An older comment here claimed OpenSSL
            // imported the public components into this lib ctx; measurement
            // disproved it (xprovider_key_probe.c) — the key keeps its
            // creating provider and the operation is served THERE, so
            // accepting the object executed outside this provider.
            JODSAPublicKey joPub = (JODSAPublicKey) publicKey;
            if (!joPub.getSpec().usableBy(keyFactory.ownProviderInstance()))
            {
                throw new InvalidKeyException(
                        "public key was created by a different Jostle provider instance; "
                                + "encode it with getEncoded() and decode it through this "
                                + "provider's KeyFactory");
            }
            return joPub;
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
            // Both halves; the library one has teeth only in the unbound
            // direct-SPI realm.
            // One message for both halves, deliberately - see PKEYKeySpec.usableBy.
            if (joKey.getSpec().getSpecNI() != keyFactory.ownSpecNI()
                    || !joKey.getSpec().usableBy(keyFactory.ownProviderInstance()))
            {
                // Keys are bound to the interface library (and OSSL_LIB_CTX)
                // that created them; JSL and JSLFIPS keys must not cross
                // implicitly.
                throw new InvalidKeyException(
                        "private key was created by a different Jostle provider instance; encode it with getEncoded() and decode it through this provider's KeyFactory");
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
        synchronized (this)
        {
            JODSAPublicKey key = importPublic(publicKey);
            lastKey = key;
            initVerifyInternal(key);
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
            try
            {
                initSignInternal(key);
            }
            catch (ProviderCapabilityException e)
            {
                // The loaded provider verifies DSA signatures but refuses to
                // generate them (OpenSSL's 3.5+ FIPS module gates signing
                // behind its "sign-check" indicator). InvalidKeyException is
                // the JCE-canonical initSign failure AND the provider-fallback
                // trigger, so a deployment that also registers a signing-capable
                // provider falls through to it instead of dying on a runtime
                // exception. Not detectable before init: the same key verifies
                // fine, and 3.1.2 signs with it.
                throw new InvalidKeyException(e.getMessage(), e);
            }
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
                // MT-39, ruled by Megan 2026-09-02: "if BC or the JCE accept
                // zero length signatures then we should too" - and measured,
                // BOTH references THROW here, so the rule's OR clause never
                // engages for DSA and we throw as well.
                //
                // A zero-length signature is not a DSA signature that fails to
                // verify; it is structurally impossible, since the DER SEQUENCE
                // carrying (r, s) cannot be empty. Returning false said "this
                // signature did not match", a different and weaker claim. Our own
                // NONEwithDSA path already threw, so this also removes an
                // inconsistency between two entry points of this same class.
                //
                // The null case rides the same guard - disclosed, not assumed: we
                // previously raised IllegalArgumentException here, where verify() declares
                // SignatureException and BouncyCastle raises it. (The JDK raises a
                // raw NullPointerException for DSA - its own defect, not a target.)
                if (sigBytes == null || sigBytes.length == 0)
                {
                    throw new SignatureException(
                            "signature is " + (sigBytes == null ? "null" : "empty")
                                    + "; a DSA signature cannot be");
                }

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
     * silently swap it for the project default. Mirrors
     * {@code ECDSASignatureSpi}.
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
}
