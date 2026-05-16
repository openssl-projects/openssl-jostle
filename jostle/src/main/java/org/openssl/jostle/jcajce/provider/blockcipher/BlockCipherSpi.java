/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


class BlockCipherSpi extends CipherSpi
{
    final OSSLCipher mandatedCipher;
    final OSSLMode mandatedMode;
    final String keyAlgorithm;

    OSSLCipher osslCipher;
    OSSLMode osslMode;
    int padding;
    OSSLBlockCipherRefWrapper refWrapper;
    int blockSize;
    int opMode;

    private static int BUF_SIZE = 1024;

    private static final BlockCipherNI blockCipherNi = NISelector.BlockCipherNI;

    Class[] availableSpecs = new Class[]{
            IvParameterSpec.class,
            GCMParameterSpec.class,
    };

    BlockCipherSpi(Object params, String expectedKeyAlgorithm)
    {
        mandatedCipher = null;
        mandatedMode = null;
        this.keyAlgorithm = expectedKeyAlgorithm;
    }

    BlockCipherSpi(OSSLCipher osslCipher, String expectedKeyAlgorithm)
    {
        mandatedCipher = osslCipher;
        mandatedMode = null;
        this.keyAlgorithm = expectedKeyAlgorithm;
    }

    BlockCipherSpi(OSSLCipher osslCipher, OSSLMode osslMode, String expectedKeyAlgorithm)
    {
        mandatedCipher = osslCipher;
        mandatedMode = osslMode;
        this.keyAlgorithm = expectedKeyAlgorithm;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        String resolved = "CFB".equalsIgnoreCase(mode) ? "CFB128" : mode;
        try
        {
            osslMode = OSSLMode.valueOf(resolved);
        }
        catch (IllegalArgumentException ex)
        {
            // Translate to the JCE-contracted exception type for unknown
            // modes; valueOf throws IllegalArgumentException directly.
            throw new NoSuchAlgorithmException("cipher mode " + mode + " not supported");
        }

        if (mandatedMode != null && mandatedMode != osslMode)
        {
            throw new NoSuchAlgorithmException("cipher mode " + osslMode + " not supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        padding = Strings.toUpperCase(padding).trim();
        if (padding.equals("NOPADDING"))
        {
            this.padding = 0;
        }
        else
        {
            if (padding.equals("PKCS7PADDING") || padding.equals("PKCS5PADDING"))
            {
                this.padding = 1;
            }
        }
    }

    /**
     * JCE convention is IllegalStateException for pre-init misuse; without
     * this guard the entry points below would throw NullPointerException on
     * the first refWrapper.getReference() call, which is a leaky abstraction.
     */
    private void requireInitialized()
    {
        if (refWrapper == null)
        {
            throw new IllegalStateException("cipher not initialized");
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        synchronized (this)
        {
            requireInitialized();

            if (blockSize == 0)
            {
                blockSize = blockCipherNi.getBlockSize(refWrapper.getReference());
            }

            return blockSize;
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        synchronized (this)
        {
            requireInitialized();
            return blockCipherNi.getFinalSize(refWrapper.getReference(), inputLen);
        }
    }

    @Override
    protected byte[] engineGetIV()
    {
        throw new IllegalStateException("not implemented");
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        throw new IllegalStateException("not implemented");
    }

    /**
     * Translate {@code Cipher.WRAP_MODE} / {@code Cipher.UNWRAP_MODE} into
     * the {@code ENCRYPT_MODE} / {@code DECRYPT_MODE} pair the native
     * layer understands. The wrap/unwrap distinction lives at the SPI
     * level (in {@link #engineWrap} / {@link #engineUnwrap}); the
     * underlying {@code EVP_*} machinery only knows encrypt and decrypt.
     */
    private static int toCryptoMode(int opmode)
    {
        if (opmode == Cipher.WRAP_MODE)
        {
            return Cipher.ENCRYPT_MODE;
        }
        if (opmode == Cipher.UNWRAP_MODE)
        {
            return Cipher.DECRYPT_MODE;
        }
        return opmode;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        validateKeyAlg(key);
        synchronized (this)
        {
            ensureNativeReference();

            blockSize = 0;
            int nativeOpmode = toCryptoMode(opmode);
            this.opMode = nativeOpmode;

            byte[] keyBytes = key.getEncoded();
            try
            {
                blockCipherNi.init(refWrapper.getReference(), nativeOpmode, keyBytes, null, 0);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new RuntimeException(e);
            }
            engineGetBlockSize();
        }
    }


    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        validateKeyAlg(key);
        synchronized (this)
        {
            ensureNativeReference();
            byte[] keyBytes = key.getEncoded();
            ErrorCode codes;
            final byte[] ivBytes;
            int tagLen;
            blockSize = 0;
            int nativeOpmode = toCryptoMode(opmode);
            this.opMode = nativeOpmode;

            if (params == null)
            {
                ivBytes = null;
                tagLen = 0;
            }
            else
            {
                if (params instanceof IvParameterSpec)
                {
                    ivBytes = ((IvParameterSpec) params).getIV();
                    if (osslMode == OSSLMode.GCM)
                    {
                        tagLen = 16;
                    }
                    else
                    {
                        tagLen = 0;
                    }

                }
                else
                {
                    if (params instanceof GCMParameterSpec)
                    {
                        ivBytes = ((GCMParameterSpec) params).getIV();
                        tagLen = (((GCMParameterSpec) params).getTLen() + 7) / 8;
                    }
                    else
                    {
                        throw new InvalidAlgorithmParameterException("unsupported parameter spec: " + params);
                    }
                }
            }

            blockCipherNi.init(refWrapper.getReference(), nativeOpmode, keyBytes, ivBytes, tagLen);

            engineGetBlockSize();
        }
    }


    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {

        validateKeyAlg(key);
        AlgorithmParameterSpec paramSpec = null;

        if (params != null)
        {
            for (int i = 0; i != availableSpecs.length; i++)
            {
                try
                {
                    paramSpec = params.getParameterSpec(availableSpecs[i]);
                    break;
                }
                catch (Exception e)
                {
                    // try next spec
                }
            }

            if (paramSpec == null)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }


        engineInit(opmode, key, paramSpec, random);

    }


    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len)
    {
        synchronized (this)
        {
            requireInitialized();
            blockCipherNi.updateAAD(refWrapper.getReference(), src, offset, len);
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src)
    {
        int remaining = src.remaining();
        if (remaining < 1)
        {
            // No data to update
        }
        else
        {
            if (src.hasArray())
            {
                engineUpdateAAD(src.array(), src.arrayOffset() + src.position(), remaining);
                src.position(src.limit());
            }
            else
            {
                if (remaining <= BUF_SIZE)
                {
                    byte[] data = new byte[remaining];
                    src.get(data);
                    engineUpdateAAD(data, 0, data.length);
                    Arrays.fill(data, (byte) 0);
                }
                else
                {
                    byte[] data = new byte[BUF_SIZE];
                    do
                    {
                        int length = Math.min(data.length, remaining);
                        src.get(data, 0, length);
                        engineUpdateAAD(data, 0, length);
                        remaining -= length;
                    }
                    while (remaining > 0);
                    Arrays.fill(data, (byte) 0);
                }
            }
        }

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        synchronized (this)
        {
            requireInitialized();
            int len = blockCipherNi.getUpdateSize(refWrapper.getReference(), inputLen);
            byte[] output = new byte[len];

            try
            {
                len = blockCipherNi.update(
                        refWrapper.getReference(),
                        output,
                        0,
                        input,
                        inputOffset, inputLen);
            }
            catch (Exception ex)
            {
                throw new RuntimeException(ex.getMessage(), ex);
            }


            return output.length == len ? output : Arrays.copyOf(output, len);
        }
    }


    /**
     * ByteBuffer override. CipherSpi provides a default that funnels through
     * the byte[] path, but it allocates an intermediate buffer per call even
     * when both buffers are array-backed; this override sidesteps that copy
     * when possible and keeps the position bookkeeping in one place.
     *
     * Behaviour:
     *   - input.position() advances by inLen on success;
     *   - output.position() advances by `written` on success;
     *   - on ShortBufferException both positions are unchanged (per JCE).
     */
    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output) throws ShortBufferException
    {
        synchronized (this)
        {
            requireInitialized();

            int inLen = input.remaining();
            if (inLen == 0)
            {
                return 0;
            }

            // Resolve input bytes without committing input.position() yet —
            // a thrown ShortBufferException must leave the buffer untouched.
            byte[] inputArray;
            int inputOffset;
            int inputStartPos = input.position();
            boolean inputOwned = false; // true if we allocated a transient copy
            if (input.hasArray())
            {
                inputArray = input.array();
                inputOffset = input.arrayOffset() + inputStartPos;
            }
            else
            {
                inputArray = new byte[inLen];
                input.get(inputArray);
                input.position(inputStartPos); // restore — we'll commit after success
                inputOffset = 0;
                inputOwned = true;
            }

            try
            {
                if (output.hasArray())
                {
                    int outputStartPos = output.position();
                    int written = engineUpdate(inputArray, inputOffset, inLen,
                            output.array(),
                            output.arrayOffset() + outputStartPos);
                    input.position(inputStartPos + inLen);
                    output.position(outputStartPos + written);
                    return written;
                }
                else
                {
                    // Output is a direct buffer; route via the byte[]-returning
                    // engineUpdate which sizes its own staging buffer correctly,
                    // then copy out. ShortBufferException is raised before any
                    // position is advanced.
                    byte[] result = engineUpdate(inputArray, inputOffset, inLen);
                    if (output.remaining() < result.length)
                    {
                        Arrays.fill(result, (byte) 0);
                        throw new ShortBufferException("output buffer too small");
                    }
                    output.put(result);
                    input.position(inputStartPos + inLen);
                    Arrays.fill(result, (byte) 0);
                    return result.length;
                }
            }
            finally
            {
                if (inputOwned)
                {
                    Arrays.fill(inputArray, (byte) 0);
                }
            }
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException
    {
        synchronized (this)
        {
            requireInitialized();
            int k = engineGetOutputSize(inputLen);
            if (output.length - outputOffset < k)
            {
                throw new ShortBufferException("output buffer too small");
            }

            byte[] workingInput = input;


            if (input == output)
            {
                if (overlap(inputOffset, inputLen, outputOffset, k))
                {
                    workingInput = new byte[inputLen];
                    System.arraycopy(input, inputOffset, workingInput, 0, inputLen);
                    inputOffset = 0;
                }
            }


            try
            {
                return blockCipherNi.update(
                        refWrapper.getReference(),
                        output,
                        outputOffset,
                        workingInput,
                        inputOffset,
                        inputLen);
            }
            catch (IllegalBlockSizeException ibsx)
            {
                throw new RuntimeException(ibsx.getMessage(), ibsx);
            }

        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException
    {
        synchronized (this)
        {
            requireInitialized();
            int len = blockCipherNi.getFinalSize(refWrapper.getReference(), inputLen);
            byte[] output = new byte[len];
            try
            {
                int written = engineDoFinal(input, inputOffset, inputLen, output, 0);
                return written == output.length ? output : Arrays.copyOf(output, written);
            }
            catch (ShortBufferException sbe)
            {
                throw new IllegalBlockSizeException(sbe.getMessage());
            }
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {

        synchronized (this)
        {
            requireInitialized();
            int k = blockCipherNi.getFinalSize(refWrapper.getReference(), inputLen);

            if (outputOffset + k > output.length)
            {
                throw new ShortBufferException("output buffer too small");
            }


            byte[] workingInput = input;


            if (input == output) // same array
            {
                if (overlap(inputOffset, inputLen, outputOffset, k))
                {
                    workingInput = new byte[inputLen];
                    System.arraycopy(input, inputOffset, workingInput, 0, inputLen);
                    inputOffset = 0;
                }
            }


            int written = 0;
            int code = blockCipherNi.update(refWrapper.getReference(), output, outputOffset, workingInput, inputOffset, inputLen);

            written += code;

            code = blockCipherNi.doFinal(refWrapper.getReference(), output, outputOffset + written);

            written += code;
            return written;
        }
    }


    /**
     * Wrap a key. The default {@code CipherSpi} implementation throws
     * {@code UnsupportedOperationException}; we override it so a Cipher
     * initialised in {@code Cipher.WRAP_MODE} with a backing wrap-capable
     * mode (AES-KW / AES-KWP via {@code OSSLMode.WRAP} / {@code WRAP_PAD})
     * can drive the standard {@code Cipher.wrap(Key)} entry point.
     * Implemented as a thin delegation onto {@code engineDoFinal} — for
     * wrap modes the entire output comes out of {@code EVP_EncryptUpdate}
     * (called from {@code engineDoFinal} via the NI update path); the
     * subsequent {@code EVP_EncryptFinal} returns zero bytes which is
     * exactly the spec-defined behaviour for these modes.
     */
    @Override
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException
    {
        if (key == null)
        {
            throw new InvalidKeyException("cannot wrap null key");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("cannot extract encoded form of key");
        }
        if (encoded.length == 0)
        {
            throw new InvalidKeyException("cannot wrap zero-length key");
        }
        try
        {
            return engineDoFinal(encoded, 0, encoded.length);
        }
        catch (BadPaddingException e)
        {
            // Wrap modes shouldn't surface BadPaddingException during
            // encrypt; if they do, the contract still requires us to
            // funnel it through IllegalBlockSizeException for the wrap
            // entry point.
            throw new IllegalBlockSizeException(e.getMessage());
        }
        catch (RuntimeException e)
        {
            // Native-side rejection of malformed wrap input (e.g.
            // RFC 3394 requires the plaintext to be a multiple of 8
            // bytes; an unaligned input fails inside EVP_EncryptUpdate
            // and propagates as an OpenSSLException). JCE callers
            // expect a checked exception from Cipher.wrap(); collapse
            // these into IllegalBlockSizeException with the OpenSSL
            // detail preserved as the cause.
            throw (IllegalBlockSizeException) new IllegalBlockSizeException(
                    "wrap failed: " + e.getMessage()).initCause(e);
        }
    }

    /**
     * Unwrap previously-wrapped key material. Mirror of {@link #engineWrap}
     * — the bulk decrypt happens in {@code engineDoFinal}, and we re-hydrate
     * the resulting bytes into the right {@code Key} object based on
     * {@code wrappedKeyType}. JCE convention is that an unwrap failure —
     * whether structural (wrong wrap algorithm, ICV mismatch) or downstream
     * (KeyFactory rejecting the encoded form) — surfaces as
     * {@code InvalidKeyException}, never {@code BadPaddingException} (which
     * would be a Bleichenbacher-style oracle).
     */
    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException
    {
        if (wrappedKey == null)
        {
            throw new InvalidKeyException("wrapped key is null");
        }
        if (wrappedKeyAlgorithm == null)
        {
            throw new NoSuchAlgorithmException("wrapped-key algorithm is null");
        }
        byte[] encoded;
        try
        {
            encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new InvalidKeyException("unwrap failed: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new InvalidKeyException("unwrap failed: " + e.getMessage(), e);
        }
        catch (RuntimeException e)
        {
            // RFC 3394 / 5649 ICV-mismatch and wrong-KEK failures surface
            // through the native layer as OpenSSLException (a runtime
            // exception). JCE convention is that all unwrap failures
            // become InvalidKeyException — never a checked padding
            // exception (Bleichenbacher channel).
            throw new InvalidKeyException("unwrap failed: " + e.getMessage(), e);
        }

        switch (wrappedKeyType)
        {
            case Cipher.SECRET_KEY:
                return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
            case Cipher.PUBLIC_KEY:
                try
                {
                    KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm);
                    return kf.generatePublic(new X509EncodedKeySpec(encoded));
                }
                catch (InvalidKeySpecException e)
                {
                    throw new InvalidKeyException("unwrap: invalid X.509 SubjectPublicKeyInfo: " + e.getMessage(), e);
                }
            case Cipher.PRIVATE_KEY:
                try
                {
                    KeyFactory kf = KeyFactory.getInstance(wrappedKeyAlgorithm);
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                }
                catch (InvalidKeySpecException e)
                {
                    throw new InvalidKeyException("unwrap: invalid PKCS#8 PrivateKeyInfo: " + e.getMessage(), e);
                }
            default:
                throw new InvalidKeyException("unknown wrapped-key type " + wrappedKeyType);
        }
    }


    /**
     * Ensure a valid native reference
     */
    protected void ensureNativeReference()
    {
        synchronized (this)
        {
            if (refWrapper == null)
            {
                long ref = blockCipherNi.makeInstance(osslCipher.ordinal(), osslMode.ordinal(), padding);
                refWrapper = new OSSLBlockCipherRefWrapper(ref, osslCipher.name());
            }
        }
    }


    protected static class Disposer
            extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            blockCipherNi.dispose(reference);
        }
    }

    protected static class OSSLBlockCipherRefWrapper
            extends NativeReference
    {

        public OSSLBlockCipherRefWrapper(long reference)
        {
            super(reference, "");
        }

        public OSSLBlockCipherRefWrapper(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        public Runnable createAction()
        {
            return new BlockCipherSpi.Disposer(reference);
        }
    }

    @Override
    public String toString()
    {
        return String.format("%s(%s)", osslMode.name(), osslCipher.name());
    }


    protected boolean overlap(int inputOffset, int inputLen, int outputOffset, int outputLen)
    {
        return inputOffset == outputOffset || Math.max(inputOffset, outputOffset) <= Math.min(inputOffset + inputLen, outputOffset + outputLen);
    }

    protected void validateKeyAlg(Key key) throws InvalidKeyException
    {
        if (keyAlgorithm.equals(key.getAlgorithm()))
        {
            return;
        }
        throw new InvalidKeyException("unsupported key algorithm " + key.getAlgorithm());
    }

}
