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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

/**
 * RSA-PKCS#1 v1.5 Cipher SPI (RSAES-PKCS1-v1_5). Reached through:
 * <ul>
 *   <li>{@code Cipher.getInstance("RSA/ECB/PKCS1Padding")}</li>
 *   <li>{@code Cipher.getInstance("RSA/None/PKCS1Padding")}</li>
 * </ul>
 *
 * <p><b>Security note.</b> PKCS#1 v1.5 encryption is structurally
 * vulnerable to Bleichenbacher-style padding-oracle attacks. OpenSSL
 * 3.x mitigates this by enabling implicit rejection by default — the
 * decryptor produces a deterministic-length pseudo-random plaintext on
 * padding failure rather than signalling the failure. Callers should
 * still prefer {@code RSA/ECB/OAEPPadding} for new applications.
 *
 * <p>OAEP-style buffering: {@link #engineUpdate} accumulates input,
 * {@link #engineDoFinal} performs the encrypt or decrypt in a single
 * native call.
 */
public class RSAPKCS1CipherSpi extends CipherSpi
{
    private static final RSAPKCS1CipherNI cipherNI = NISelector.RSAPKCS1CipherNI;

    private CipherRef ref;
    private int opMode;
    private int modulusBytes;
    private RandSource randSource = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /**
     * Pin the most recently bound key reachable so its {@code PKEYKeySpec}'s
     * native handle stays alive across every native call. Without this
     * field the JIT can mark {@code key}'s stack slot dead immediately
     * after extracting the long handle in {@code engineInit}, GC then
     * reclaims the spec, the disposer fires, and the in-flight native
     * call uses a freed {@code EVP_PKEY}.
     */
    private RSAKey lastKey = null;


    public RSAPKCS1CipherSpi() {}


    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
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
        String upper = padding.trim().toUpperCase(Locale.ROOT);
        if (!"PKCS1PADDING".equals(upper))
        {
            throw new NoSuchPaddingException("padding " + padding + " not supported");
        }
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
        // JCE Cipher.getOutputSize already throws IllegalStateException
        // when the cipher isn't initialised, so this method is only
        // invoked post-init (modulusBytes is populated by engineInit).
        // Reject explicitly if a direct SPI invocation reaches this
        // method pre-init, rather than returning a bogus value.
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
            // PKCS#1 v1.5 takes no algorithm parameters.
            if (params != null)
            {
                throw new InvalidAlgorithmParameterException(
                        "PKCS#1 v1.5 RSA does not accept algorithm parameters");
            }

            long keyRef;
            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
            {
                // Accept any RSAPublicKey (incl. a foreign cert key) by
                // translating to a JSL key; pin the JSL key, which owns the
                // native handle, reachable across the native call.
                JORSAPublicKey pub = RSAKeyImport.importPublic(key, "encrypt/wrap requires an RSAPublicKey");
                lastKey = pub;
                keyRef = pub.getSpec().getReference();
                modulusBytes = bigIntByteLen(pub.getModulus());
                this.opMode = RSAPKCS1CipherNI.OP_ENCRYPT;
            }
            else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
            {
                JORSAPrivateKey priv = RSAKeyImport.importPrivate(key, "decrypt/unwrap requires an RSAPrivateKey");
                lastKey = priv;
                keyRef = priv.getSpec().getReference();
                modulusBytes = bigIntByteLen(priv.getModulus());
                this.opMode = RSAPKCS1CipherNI.OP_DECRYPT;
            }
            else
            {
                throw new InvalidAlgorithmParameterException("unsupported opmode " + opmode);
            }

            this.randSource = DefaultRandSource.replaceWith(this.randSource, random);

            ensureRef();
            cipherNI.init(ref.getReference(), keyRef, this.opMode, this.randSource);

            buffer.reset();
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException(
                    "PKCS#1 v1.5 RSA does not accept algorithm parameters");
        }
        engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
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
            engineUpdate(input, inputOffset, inputLen);
            byte[] in = buffer.toByteArray();
            buffer.reset();

            try
            {
                int needed = cipherNI.doFinal(ref.getReference(),
                        in, 0, in.length,
                        null, 0,
                        randSource);
                byte[] out = new byte[needed];
                int written = cipherNI.doFinal(ref.getReference(),
                        in, 0, in.length,
                        out, 0,
                        randSource);
                if (written == out.length)
                {
                    return out;
                }
                byte[] trimmed = new byte[written];
                System.arraycopy(out, 0, trimmed, 0, written);
                return trimmed;
            }
            catch (org.openssl.jostle.jcajce.provider.OpenSSLException e)
            {
                if (opMode == RSAPKCS1CipherNI.OP_DECRYPT)
                {
                    throw (BadPaddingException) new BadPaddingException(e.getMessage()).initCause(e);
                }
                throw (IllegalBlockSizeException) new IllegalBlockSizeException(e.getMessage()).initCause(e);
            }
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length)
        {
            throw new ShortBufferException(
                    "output too small: need " + result.length + " bytes");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException
    {
        synchronized (this)
        {
            requireInitialised();
            if (opMode != RSAPKCS1CipherNI.OP_ENCRYPT)
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
                throw new IllegalStateException("unexpected BadPaddingException during wrap", impossible);
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
            if (opMode != RSAPKCS1CipherNI.OP_DECRYPT)
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
                // JCE convention: surface as InvalidKeyException to avoid
                // exposing padding-failure detail through the unwrap channel.
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
                // SecretKeySpec rejects empty / null key bytes with
                // IllegalArgumentException. This fires when PKCS#1
                // implicit rejection returns a zero-length synthetic
                // plaintext for a tampered ciphertext on OpenSSL
                // versions / platforms where the synthetic length
                // collapses (observed on OpenSSL 3.6 on ARM under
                // unitTest17). Per JCE convention,
                // Cipher.unwrap must surface ALL unwrap failures as
                // InvalidKeyException — letting IllegalArgumentException
                // leak would break callers' typed catch clauses and
                // would also act as a side-channel signalling
                // "implicit rejection fired".
                throw (InvalidKeyException) new InvalidKeyException(
                        "unable to reconstruct unwrapped " + wrappedKeyAlgorithm + " key").initCause(e);
            }
        }
    }


    private void ensureRef()
    {
        if (ref == null)
        {
            ref = new CipherRef(cipherNI.allocateCipher(), "RSA-PKCS1");
        }
    }

    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    private static int bigIntByteLen(BigInteger v)
    {
        return (v.bitLength() + 7) / 8;
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
            NISelector.RSAPKCS1CipherNI.disposeCipher(reference);
        }
    }

    protected static class CipherRef extends NativeReference
    {
        protected CipherRef(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }
}
