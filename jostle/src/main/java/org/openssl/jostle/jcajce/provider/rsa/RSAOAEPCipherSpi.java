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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.interfaces.RSAKey;
import org.openssl.jostle.jcajce.provider.InvalidCipherTextException;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

/**
 * RSA-OAEP Cipher SPI. JCE callers reach this class through any of:
 * <ul>
 *   <li>{@code Cipher.getInstance("RSA/ECB/OAEPPadding")} — defaults to
 *       SHA-256 / MGF1-SHA-256 / empty label. (Note: this is a deliberate
 *       deviation from the JCE historical SHA-1 default, matching the
 *       PSS policy elsewhere in this provider.)</li>
 *   <li>{@code Cipher.getInstance("RSA/ECB/OAEPWith<digest>AndMGF1Padding")} —
 *       uses the embedded digest for both the OAEP hash and the MGF1
 *       hash. Initialisation with an explicit {@link OAEPParameterSpec}
 *       overrides this.</li>
 *   <li>{@code Cipher.getInstance("RSA")} — bare; caller must invoke
 *       {@code init} with an {@link OAEPParameterSpec}.</li>
 * </ul>
 *
 * <p>OAEP is one-shot: every call to
 * {@link #engineUpdate} accumulates input into a buffer and returns
 * an empty array; the actual encrypt or decrypt happens at
 * {@link #engineDoFinal}. The buffer is bounded by
 * {@code key_size_bytes - 2*hash_size - 2}; OpenSSL enforces the limit.
 */
public class RSAOAEPCipherSpi extends CipherSpi
{
    // Instance fields, not NISelector statics: the SPI is bound to whichever
    // NI backend its provider passes in (NISelector for JSL, FIPSNISelector
    // for JSLFIPS); foreign keys translate through the matching KeyFactory.
    private final RSAOAEPCipherNI cipherNI;
    private final RSAKeyFactorySpi keyFactory;

    /** Modern safe default — see class javadoc. */
    private static final String DEFAULT_DIGEST = "SHA-256";

    private String oaepDigest = DEFAULT_DIGEST;
    private String mgf1Digest = DEFAULT_DIGEST;
    private byte[] label = null;

    /**
     * Set by {@link #engineSetPadding} when the padding string carries
     * an embedded digest. When non-null this is the SPI-level digest
     * that {@link #engineInit} will use unless overridden by an
     * explicit {@link OAEPParameterSpec}.
     */
    private String paddingDigest = null;

    private CipherRef ref;
    private int opMode;
    private int modulusBytes;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private final WipingByteArrayOutputStream buffer = new WipingByteArrayOutputStream();

    /**
     * Pin reference to the most recently bound key so the underlying
     * {@code PKEYKeySpec}'s native handle stays reachable across every
     * native call made from this SPI. Without this field the JIT can
     * mark {@code key}'s stack slot dead immediately after extracting
     * the long handle in {@code engineInit}, GC then reclaims the
     * spec, the disposer fires, and the in-flight native call uses
     * a freed {@code EVP_PKEY}. Mirrors the {@code lastKey} pattern
     * in {@link RSASignatureSpiBase}.
     */
    private RSAKey lastKey = null;


    public RSAOAEPCipherSpi()
    {
        this(NISelector.RSAOAEPCipherNI, new RSAKeyFactorySpi());
    }

    public RSAOAEPCipherSpi(RSAOAEPCipherNI cipherNI, RSAKeyFactorySpi keyFactory)
    {
        this.cipherNI = cipherNI;
        this.keyFactory = keyFactory;
    }


    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        // RSA is not a block cipher; "ECB" / "NONE" are accepted for
        // JCE name-form compatibility but no mode is actually applied.
        if (mode == null)
        {
            return;
        }
        String m = mode.trim().toUpperCase(Locale.ROOT);
        if (!m.isEmpty() && !"ECB".equals(m) && !"NONE".equals(m))
        {
            throw new NoSuchAlgorithmException("RSA mode " + mode + " not supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        if (padding == null)
        {
            return;
        }
        String p = padding.trim();
        String upper = p.toUpperCase(Locale.ROOT);

        if ("OAEPPADDING".equals(upper))
        {
            // Defaults applied at init time.
            paddingDigest = null;
            return;
        }
        if (upper.startsWith("OAEPWITH") && upper.endsWith("ANDMGF1PADDING"))
        {
            // Strip the "OAEPWith" prefix and "AndMGF1Padding" suffix to
            // recover the digest name in its original case.
            int prefix = "OAEPWith".length();
            int suffix = "AndMGF1Padding".length();
            String digest = p.substring(prefix, p.length() - suffix);
            paddingDigest = digest;
            return;
        }
        throw new NoSuchPaddingException("padding " + padding + " not supported");
    }

    @Override
    protected int engineGetBlockSize()
    {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        // RSA outputs are bounded by the modulus size in both directions.
        // Decrypt outputs are smaller in practice (= inputLen - 2*hash - 2)
        // but returning modulusBytes is the safe upper bound.
        //
        // JCE Cipher.getOutputSize already throws IllegalStateException
        // when the cipher isn't initialised, so this method is only
        // invoked post-init via the JCE entry point (modulusBytes is
        // populated by engineInit). A direct SPI invocation pre-init
        // would otherwise return a bogus value derived from inputLen
        // (e.g. inputLen + 64 had overflow risk for inputLen near
        // INT_MAX); reject explicitly to match the JCE convention.
        if (modulusBytes == 0)
        {
            throw new IllegalStateException("cipher not initialised");
        }
        return modulusBytes;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        // Returning null is JCE-permissible; OAEPParameterSpec is the
        // canonical way callers retrieve OAEP params and most providers
        // return null here when they were initialised with defaults.
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        synchronized (this)
        {
            // Discard any plaintext a prior abandoned operation left in the
            // accumulator up-front, so even a re-init that fails validation
            // below scrubs it — not only a successful re-init (which no longer
            // needs a trailing wipe: nothing writes to the buffer during init).
            buffer.wipe();

            // Resolve digest + MGF1 + label, in priority order:
            //   1. Explicit OAEPParameterSpec from the caller.
            //   2. Digest extracted from the padding string at engineSetPadding.
            //   3. SPI defaults (SHA-256 / SHA-256 / empty label).
            if (params == null)
            {
                String d = (paddingDigest != null) ? paddingDigest : DEFAULT_DIGEST;
                applyParameters(d, d, null);
            }
            else if (params instanceof OAEPParameterSpec)
            {
                applyOAEPSpec((OAEPParameterSpec) params);
            }
            else
            {
                throw new InvalidAlgorithmParameterException(
                        "expected OAEPParameterSpec, got " + params.getClass().getName());
            }

            // Validate key + opmode and compute modulus size for getOutputSize.
            // ENCRYPT_MODE / WRAP_MODE both map to OP_ENCRYPT (engineWrap
            // forwards to engineDoFinal under the hood). Likewise for
            // DECRYPT_MODE / UNWRAP_MODE → OP_DECRYPT.
            long keyRef;
            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
            {
                // Accept any RSAPublicKey (incl. a foreign cert key) by
                // translating to a JSL key; pin the JSL key, which owns the
                // native handle, reachable across the native call.
                JORSAPublicKey pub = RSAKeyImport.importPublic(keyFactory, key, "encrypt/wrap requires an RSAPublicKey");
                lastKey = pub;
                keyRef = pub.getSpec().getReference();
                modulusBytes = bigIntByteLen(pub.getModulus());
                this.opMode = RSAOAEPCipherNI.OP_ENCRYPT;
            }
            else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
            {
                JORSAPrivateKey priv = RSAKeyImport.importPrivate(keyFactory, key, "decrypt/unwrap requires an RSAPrivateKey");
                lastKey = priv;
                keyRef = priv.getSpec().getReference();
                modulusBytes = bigIntByteLen(priv.getModulus());
                this.opMode = RSAOAEPCipherNI.OP_DECRYPT;
            }
            else
            {
                throw new InvalidAlgorithmParameterException(
                        "unsupported opmode " + opmode);
            }

            this.randSource = DefaultRandSource.replaceWith(this.randSource, random);

            ensureRef();
            // Both encrypt and decrypt require a RandSource: encrypt for the
            // OAEP seed, decrypt for RSA blinding (timing-channel countermeasure).
            cipherNI.init(ref.getReference(), keyRef, this.opMode,
                    oaepDigest, mgf1Digest, label,
                    this.randSource);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec spec = null;
        if (params != null)
        {
            try
            {
                spec = params.getParameterSpec(OAEPParameterSpec.class);
            }
            catch (java.security.spec.InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException(
                        "expected OAEPParameterSpec via AlgorithmParameters", e);
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        synchronized (this)
        {
            requireInitialised();
            if (input != null && inputLen > 0)
            {
                buffer.write(input, inputOffset, inputLen);
            }
            return null;
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
    {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException
    {
        synchronized (this)
        {
            requireInitialised();
            byte[] in = null;
            byte[] out = null;
            try
            {
                engineUpdate(input, inputOffset, inputLen);
                in = buffer.toByteArray();
                // Eager wipe (accumulator may hold plaintext key material in
                // WRAP_MODE): keep the plaintext only in `in` during the native
                // call, not also in the buffer. The finally below is the backstop
                // for the paths that never reach this line.
                buffer.wipe();

                int needed = cipherNI.doFinal(ref.getReference(),
                        in, 0, in.length,
                        null, 0,
                        randSource);
                out = new byte[needed];
                int written = cipherNI.doFinal(ref.getReference(),
                        in, 0, in.length,
                        out, 0,
                        randSource);
                if (written == out.length)
                {
                    byte[] result = out;
                    out = null; // returned to the caller — must not be scrubbed
                    return result;
                }
                byte[] trimmed = new byte[written];
                System.arraycopy(out, 0, trimmed, 0, written);
                return trimmed;
            }
            catch (InvalidCipherTextException e)
            {
                // OAEP decrypt failure (padding-check failed, ciphertext
                // out of range, etc.). The NI surfaces a dedicated
                // exception for this so JCE-canonical BadPaddingException
                // is produced without inspecting the OpenSSL error queue.
                // InvalidCipherTextException is only thrown by the OAEP
                // NI in decrypt mode, so no opMode check needed.
                throw (BadPaddingException) new BadPaddingException(e.getMessage()).initCause(e);
            }
            catch (OpenSSLException e)
            {
                // Encrypt-mode failure (input too long for modulus, etc.)
                // or any non-cipher-text decrypt-mode failure. For decrypt
                // mode, JCE convention is BadPaddingException for any
                // decrypt failure (avoid leaking distinguishability);
                // for encrypt this is closer to IllegalBlockSizeException.
                if (opMode == RSAOAEPCipherNI.OP_DECRYPT)
                {
                    throw (BadPaddingException) new BadPaddingException(e.getMessage()).initCause(e);
                }
                throw (IllegalBlockSizeException) new IllegalBlockSizeException(e.getMessage()).initCause(e);
            }
            finally
            {
                // The eager wipe above runs on the consume path; wiping again
                // here also scrubs the accumulator when engineUpdate (a bad
                // final-chunk offset/length) threw before we reached it. Then
                // clear the plaintext copies: `in` (the toByteArray copy — the
                // plaintext key on wrap) and the oversized `out` (decrypt
                // plaintext when trimmed). The directly-returned array was
                // detached above (out = null).
                buffer.wipe();
                Arrays.clear(in);
                Arrays.clear(out);
            }
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        synchronized (this)
        {
            requireInitialised();
            // Encrypt output is always exactly the modulus size. Reject an
            // undersized buffer BEFORE consuming buffered update() state, so a
            // JCE-sanctioned retry with a larger buffer doesn't silently lose the
            // earlier update() data. (Decrypt output is <= modulusBytes and not
            // known exactly without doing the op, so it keeps the
            // compute-then-check form below, matching BC/SunJCE.)
            if (opMode == RSAOAEPCipherNI.OP_ENCRYPT && output != null
                    && output.length - outputOffset < modulusBytes)
            {
                throw new ShortBufferException(
                        "output too small: need " + modulusBytes + " bytes");
            }
            byte[] result = engineDoFinal(input, inputOffset, inputLen);
            if (output.length - outputOffset < result.length)
            {
                throw new ShortBufferException(
                        "output too small: need " + result.length + " bytes");
            }
            System.arraycopy(result, 0, output, outputOffset, result.length);
            return result.length;
        }
    }


    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException
    {
        synchronized (this)
        {
            requireInitialised();
            if (opMode != RSAOAEPCipherNI.OP_ENCRYPT)
            {
                throw new IllegalStateException("cipher not initialised for wrapping");
            }
            if (key == null)
            {
                throw new InvalidKeyException("key to wrap is null");
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length == 0)
            {
                throw new InvalidKeyException(
                        "cannot wrap key without an encoded form: " + key.getAlgorithm());
            }
            try
            {
                return engineDoFinal(encoded, 0, encoded.length);
            }
            catch (BadPaddingException impossible)
            {
                // BadPaddingException only arises on decrypt; encrypt is the
                // wrap direction, so this branch is unreachable.
                throw new IllegalStateException("unexpected BadPaddingException during wrap", impossible);
            }
            finally
            {
                // Scrub the plaintext key bytes getEncoded() handed us.
                Arrays.clear(encoded);
            }
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException
    {
        synchronized (this)
        {
            requireInitialised();
            if (opMode != RSAOAEPCipherNI.OP_DECRYPT)
            {
                throw new IllegalStateException("cipher not initialised for unwrapping");
            }
            if (wrappedKey == null)
            {
                throw new InvalidKeyException("wrapped key is null");
            }
            if (wrappedKeyAlgorithm == null)
            {
                throw new InvalidKeyException("wrapped key algorithm is null");
            }

            byte[] encoded;
            try
            {
                encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            }
            catch (IllegalBlockSizeException | BadPaddingException e)
            {
                // JCE convention: any cipher-side failure during unwrap
                // surfaces as InvalidKeyException — exposing finer-grained
                // padding details would help a Bleichenbacher-style oracle.
                throw (InvalidKeyException) new InvalidKeyException(
                        "unable to unwrap " + wrappedKeyAlgorithm + " key").initCause(e);
            }

            try
            {
                switch (wrappedKeyType)
                {
                    case Cipher.SECRET_KEY:
                        return new SecretKeySpec(encoded, wrappedKeyAlgorithm);

                    case Cipher.PUBLIC_KEY:
                    {
                        KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm);
                        return kf.generatePublic(new X509EncodedKeySpec(encoded));
                    }

                    case Cipher.PRIVATE_KEY:
                    {
                        KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm);
                        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                    }

                    default:
                        throw new InvalidKeyException(
                                "unknown wrapped key type: " + wrappedKeyType);
                }
            }
            catch (InvalidKeySpecException e)
            {
                throw (InvalidKeyException) new InvalidKeyException(
                        "unable to reconstruct unwrapped " + wrappedKeyAlgorithm + " key").initCause(e);
            }
            catch (IllegalArgumentException e)
            {
                // SecretKeySpec rejects an empty/null key (and KeyFactory an empty
                // algorithm name) with IllegalArgumentException — reachable when the
                // ciphertext decrypts to a zero-length plaintext. Fold it into
                // InvalidKeyException so every unwrap failure surfaces as the JCE
                // contract type and no "empty plaintext" signal leaks. Mirrors
                // RSAPKCS1CipherSpi.
                throw (InvalidKeyException) new InvalidKeyException(
                        "unable to reconstruct unwrapped " + wrappedKeyAlgorithm + " key").initCause(e);
            }
            finally
            {
                // Scrub the decrypted key plaintext (SecretKeySpec / KeyFactory
                // copy it, so clearing here cannot corrupt the returned key).
                Arrays.clear(encoded);
            }
        }
    }


    private void applyOAEPSpec(OAEPParameterSpec spec) throws InvalidAlgorithmParameterException
    {
        String digest = spec.getDigestAlgorithm();
        if (digest == null || digest.isEmpty())
        {
            throw new InvalidAlgorithmParameterException("OAEPParameterSpec missing digest");
        }

        String mgf = spec.getMGFAlgorithm();
        if (mgf != null && !"MGF1".equalsIgnoreCase(mgf))
        {
            throw new InvalidAlgorithmParameterException(
                    "only MGF1 is supported (got " + mgf + ")");
        }

        AlgorithmParameterSpec mgfParams = spec.getMGFParameters();
        String mgfHash = digest;
        if (mgfParams instanceof MGF1ParameterSpec)
        {
            String h = ((MGF1ParameterSpec) mgfParams).getDigestAlgorithm();
            if (h != null && !h.isEmpty())
            {
                mgfHash = h;
            }
        }
        else if (mgfParams != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "unsupported MGF parameters: " + mgfParams.getClass().getName());
        }

        byte[] labelBytes = null;
        PSource pSource = spec.getPSource();
        if (pSource instanceof PSource.PSpecified)
        {
            byte[] v = ((PSource.PSpecified) pSource).getValue();
            // PSpecified.DEFAULT exposes a zero-length value — treat
            // as "no label" rather than allocating an empty array
            // through to the native side. Arrays.clone() is null-safe
            // (the project-standard helper) so a future contract change
            // returning null doesn't NPE here.
            labelBytes = (v == null || v.length == 0) ? null : Arrays.clone(v);
        }
        else if (pSource != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "unsupported PSource: " + pSource.getClass().getName());
        }

        applyParameters(digest, mgfHash, labelBytes);
    }

    private void applyParameters(String digest, String mgfHash, byte[] labelBytes)
    {
        this.oaepDigest = digest;
        this.mgf1Digest = mgfHash;
        this.label = labelBytes;
    }

    private void ensureRef()
    {
        if (ref == null)
        {
            ref = new CipherRef(cipherNI, cipherNI.allocateCipher(), "RSA-OAEP");
        }
    }

    /**
     * JCE convention is {@link IllegalStateException} for
     * pre-init misuse. Without this guard the entry points below
     * would NPE on the first {@code ref.getReference()} access.
     */
    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    private static int bigIntByteLen(BigInteger v)
    {
        // bitLength rounded up to the nearest byte.
        return (v.bitLength() + 7) / 8;
    }


    protected static class Disposer extends NativeDisposer
    {
        // The NI that allocated the cipher frees it - a FIPS-allocated
        // cipher must be disposed through the FIPS interface library.
        private final RSAOAEPCipherNI cipherNI;

        Disposer(RSAOAEPCipherNI cipherNI, long ref)
        {
            super(ref);
            this.cipherNI = cipherNI;
        }

        @Override
        protected void dispose(long reference)
        {
            cipherNI.disposeCipher(reference);
        }
    }

    protected static class CipherRef extends NativeReference
    {

        protected CipherRef(RSAOAEPCipherNI cipherNI, long reference, String name)
        {
            super(reference, name, new Disposer(cipherNI, reference));
        }

    }
}
