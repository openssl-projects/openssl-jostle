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

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.InvalidCipherTextException;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.io.ExposedByteArrayOutputStream;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Locale;

/**
 * Authenticated-encryption SPI for CCM mode (NIST SP 800-38C). CCM is
 * fundamentally one-shot at the OpenSSL layer:
 *
 * <ul>
 *   <li>The total plaintext length must be set BEFORE any AAD or
 *       plaintext is fed through {@code EVP_EncryptUpdate}.</li>
 *   <li>AAD must be passed as a single {@code EVP_EncryptUpdate} call —
 *       CCM does not support streaming AAD.</li>
 *   <li>Plaintext must be passed as a single {@code EVP_EncryptUpdate}
 *       call.</li>
 * </ul>
 *
 * This SPI accommodates JCE's streaming-update model by buffering all
 * input and AAD in {@link ExposedByteArrayOutputStream} (a Jostle port
 * of BouncyCastle's CCM-internal buffer that avoids the copy
 * {@code ByteArrayOutputStream.toByteArray()} makes). The buffered
 * data is handed to the native side as a single {@code ni_doFinal}
 * call.
 *
 * <p><strong>AAD discipline:</strong> per CLAUDE.md and CCM's
 * underlying constraint, this SPI rejects incremental AAD. The first
 * call to {@link #engineUpdateAAD} is accepted (buffered); a second
 * call throws {@link IllegalStateException}. After any
 * {@link #engineUpdate} call, subsequent {@code engineUpdateAAD}
 * also throws — JCE convention. Plaintext, by contrast, may be
 * accumulated through multiple {@code engineUpdate} calls and is
 * concatenated at {@code engineDoFinal}.
 */
public class CCMCipherSpi extends CipherSpi
{
    private static final CCMCipherNI cipherNI = NISelector.CCMCipherNI;

    /** CCM nonce length range, NIST SP 800-38C §6.1: 7..13 bytes. */
    private static final int CCM_MIN_NONCE_LEN = 7;
    private static final int CCM_MAX_NONCE_LEN = 13;

    /**
     * Default CCM tag length (bits) for the {@link IvParameterSpec} path,
     * which carries no tag length. 64 bits matches BouncyCastle's CCM
     * default (CCMBlockCipher uses macSize=64 with ParametersWithIV), so
     * the IV-only init path stays interoperable with BC.
     */
    private static final int CCM_DEFAULT_TAG_BITS = 64;

    /** Identifies the underlying block cipher family. */
    public enum CipherFamily
    {
        AES, ARIA, SM4
    }

    private final CipherFamily family;

    /* Native context. */
    private CCMRef ref;

    /* Init state. */
    private int opMode;
    private byte[] iv;
    private int tagLenBytes;

    /* Streaming buffers. */
    private final ExposedByteArrayOutputStream aadBuffer = new ExposedByteArrayOutputStream();
    private final ExposedByteArrayOutputStream dataBuffer = new ExposedByteArrayOutputStream();

    /* updateAAD discipline flags. */
    private boolean aadRejected;   // set true after first updateAAD AND after first update

    /*
     * Nonce-reuse guard (mirrors SunJCE's GCM behaviour): set true after a
     * successful ENCRYPT doFinal so a second encryption on the same
     * instance — which would reuse the nonce, catastrophic for CCM — is
     * rejected until engineInit supplies a fresh nonce. Decrypt is exempt.
     */
    private boolean encryptionReinitRequired;


    public CCMCipherSpi(CipherFamily family)
    {
        this.family = family;
    }


    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if (mode == null || !"CCM".equalsIgnoreCase(mode))
        {
            throw new NoSuchAlgorithmException("CCMCipherSpi only supports CCM mode");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        if (padding == null)
        {
            return;
        }
        String p = padding.trim().toUpperCase(Locale.ROOT);
        if (!"NOPADDING".equals(p))
        {
            throw new NoSuchPaddingException("CCM only supports NoPadding");
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        return 16;  // all CCM-capable ciphers in this provider are 128-bit block
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        if (ref == null)
        {
            throw new IllegalStateException("cipher not initialised");
        }
        long pending = (long) dataBuffer.size() + (long) inputLen;
        if (pending > Integer.MAX_VALUE)
        {
            throw new IllegalStateException("CCM output size overflows int");
        }
        if (opMode == Cipher.ENCRYPT_MODE)
        {
            // ct||tag; guard the tag addition in long so the (int) cast
            // can't overflow to a negative size (matches the C-side
            // JO_OUTPUT_TOO_LONG_INT32 guard in ccm_ctx_get_output_size).
            long needed = pending + tagLenBytes;
            if (needed > Integer.MAX_VALUE)
            {
                throw new IllegalStateException("CCM output size overflows int");
            }
            return (int) needed;
        }
        // Decrypt: input contains the tag, output is shorter.
        return (int) Math.max(0L, pending - tagLenBytes);
    }

    @Override
    protected byte[] engineGetIV()
    {
        return iv == null ? null : Arrays.clone(iv);
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        // Following the same convention as RSAOAEPCipherSpi — return
        // null. Callers retrieve params via the spec class.
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        // CCM requires a nonce; rejecting init-without-params is the JCE
        // convention for AEAD modes. InvalidKeyException is the only
        // checked exception this overload may throw, and surfacing it (vs
        // an unchecked IllegalArgumentException) preserves JCE provider
        // fallback.
        throw new InvalidKeyException("CCM requires a GCMParameterSpec (tagLen + nonce)");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        int tagBits;
        byte[] nonce;
        if (params instanceof GCMParameterSpec)
        {
            GCMParameterSpec spec = (GCMParameterSpec) params;
            tagBits = spec.getTLen();
            nonce = spec.getIV();
        }
        else if (params instanceof IvParameterSpec)
        {
            // IvParameterSpec carries only the nonce; default the tag to
            // CCM_DEFAULT_TAG_BITS (64) to match BouncyCastle's CCM
            // IV-only default.
            nonce = ((IvParameterSpec) params).getIV();
            tagBits = CCM_DEFAULT_TAG_BITS;
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                    "CCM requires a GCMParameterSpec (tagLen in bits + nonce) " +
                    "or an IvParameterSpec (nonce; tag defaults to 64 bits)");
        }
        // (tagBits & 7) == (tagBits % 8) here because tagBits is always
        // non-negative — GCMParameterSpec.getTLen() is >= 0 by construction
        // and the IvParameterSpec path uses 64 — so this rejects any tag
        // length that is not a whole number of bytes.
        if ((tagBits & 7) != 0)
        {
            throw new InvalidAlgorithmParameterException(
                    "CCM tag length must be a multiple of 8 bits");
        }
        int tagBytes = tagBits / 8;
        if (nonce == null)
        {
            throw new InvalidAlgorithmParameterException("CCM nonce is null");
        }
        // Validate nonce + tag length at the JCE boundary so a bad value
        // surfaces as InvalidAlgorithmParameterException with a useful
        // message, rather than reaching the native layer and returning a
        // JO_INVALID_IV_LEN / JO_INVALID_TAG_LEN that maps to a generic
        // IllegalStateException (and breaks JCE provider fallback).
        if (nonce.length < CCM_MIN_NONCE_LEN || nonce.length > CCM_MAX_NONCE_LEN)
        {
            throw new InvalidAlgorithmParameterException(
                    "CCM nonce must be " + CCM_MIN_NONCE_LEN + ".." + CCM_MAX_NONCE_LEN +
                    " bytes (got " + nonce.length + ")");
        }
        if (!isValidCcmTagLen(tagBytes))
        {
            throw new InvalidAlgorithmParameterException(
                    "CCM tag length must be 32, 48, 64, 80, 96, 112, or 128 bits (got " + tagBits + ")");
        }

        byte[] keyBytes = (key == null) ? null : key.getEncoded();
        if (keyBytes == null)
        {
            throw new InvalidKeyException("key has no encoded form");
        }

        OSSLCipher osslCipher = resolveCipherForKeyLen(keyBytes.length);

        // Dispose any previously-allocated native ref.
        disposeRef();

        // synchronized(this) keeps this SPI (and therefore its CCMRef and
        // the native ctx the ref owns) reachable across the native calls,
        // so GC + the disposer can't free the ctx mid-call. The java9
        // override replaces this with Reference.reachabilityFence(this).
        synchronized (this)
        {
            // Allocate a new native ctx for this cipher family + key size.
            ref = new CCMRef(cipherNI.makeInstance(osslCipher.ordinal()), "CCM-" + osslCipher.name());

            // Init the native ctx. ni_init records key/iv/tag_len + opMode
            // and validates ranges; actual EVP work happens at doFinal.
            cipherNI.init(ref.getReference(), opmode, keyBytes, nonce, tagBytes);
        }

        this.opMode = opmode;
        this.iv = Arrays.clone(nonce);
        this.tagLenBytes = tagBytes;
        this.aadRejected = false;
        this.encryptionReinitRequired = false;
        this.aadBuffer.reset();
        this.dataBuffer.reset();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            engineInit(opmode, key, random);
            return;
        }
        try
        {
            engineInit(opmode, key, params.getParameterSpec(GCMParameterSpec.class), random);
        }
        catch (java.security.spec.InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException("CCM init: " + e.getMessage(), e);
        }
    }

    /** Resolve OSSLCipher for this family + key length. */
    private OSSLCipher resolveCipherForKeyLen(int keyLen) throws InvalidKeyException
    {
        switch (family)
        {
            case AES:
                switch (keyLen)
                {
                    case 16: return OSSLCipher.AES128;
                    case 24: return OSSLCipher.AES192;
                    case 32: return OSSLCipher.AES256;
                    default:
                        throw new InvalidKeyException(
                                "AES-CCM key must be 16, 24, or 32 bytes (got " + keyLen + ")");
                }
            case ARIA:
                switch (keyLen)
                {
                    case 16: return OSSLCipher.ARIA128;
                    case 24: return OSSLCipher.ARIA192;
                    case 32: return OSSLCipher.ARIA256;
                    default:
                        throw new InvalidKeyException(
                                "ARIA-CCM key must be 16, 24, or 32 bytes (got " + keyLen + ")");
                }
            case SM4:
                if (keyLen != 16)
                {
                    throw new InvalidKeyException("SM4-CCM key must be 16 bytes (got " + keyLen + ")");
                }
                return OSSLCipher.SM4;
            default:
                throw new InvalidKeyException("unknown CCM family " + family);
        }
    }

    /** CCM tag length valid set per NIST SP 800-38C §6.1: {4,6,8,10,12,14,16} bytes. */
    private static boolean isValidCcmTagLen(int tagBytes)
    {
        switch (tagBytes)
        {
            case 4: case 6: case 8: case 10: case 12: case 14: case 16:
                return true;
            default:
                return false;
        }
    }


    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len)
    {
        requireInitialised();
        checkEncryptionReinit();
        // AAD must be supplied BEFORE any plaintext, AND in a single call.
        if (aadRejected)
        {
            throw new IllegalStateException(
                    "CCM does not support incremental AAD; updateAAD may be called at most once before update");
        }
        aadBuffer.write(src, offset, len);
        aadRejected = true;
    }

    @Override
    protected void engineUpdateAAD(java.nio.ByteBuffer src)
    {
        if (src == null)
        {
            return;
        }
        requireInitialised();
        checkEncryptionReinit();
        if (aadRejected)
        {
            throw new IllegalStateException(
                    "CCM does not support incremental AAD; updateAAD may be called at most once before update");
        }
        int remaining = src.remaining();
        if (remaining == 0)
        {
            aadRejected = true;
            return;
        }
        if (src.hasArray())
        {
            aadBuffer.write(src.array(), src.arrayOffset() + src.position(), remaining);
            src.position(src.position() + remaining);
        }
        else
        {
            byte[] tmp = new byte[remaining];
            src.get(tmp);
            aadBuffer.write(tmp, 0, remaining);
        }
        aadRejected = true;
    }


    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        requireInitialised();
        checkEncryptionReinit();
        // Any update closes the AAD window per JCE convention.
        aadRejected = true;
        if (input != null && inputLen > 0)
        {
            dataBuffer.write(input, inputOffset, inputLen);
        }
        // CCM produces no output incrementally.
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
    {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException
    {
        requireInitialised();
        checkEncryptionReinit();
        if (input != null && inputLen > 0)
        {
            dataBuffer.write(input, inputOffset, inputLen);
        }
        int outputSize = engineGetOutputSize(0);
        byte[] output = new byte[outputSize];
        try
        {
            int written;
            try
            {
                written = doFinalInternal(output, 0);
            }
            catch (InvalidCipherTextException ex)
            {
                // CCM tag-check failure — JCE-canonical translation.
                AEADBadTagException jceEx = new AEADBadTagException(ex.getMessage());
                jceEx.initCause(ex);
                throw jceEx;
            }
            // A successful encrypt consumes the nonce; block reuse until re-init.
            if (opMode == Cipher.ENCRYPT_MODE)
            {
                encryptionReinitRequired = true;
            }
            if (written == output.length)
            {
                return output;
            }
            // Trim down to the actual length.
            byte[] trimmed = new byte[written];
            System.arraycopy(output, 0, trimmed, 0, written);
            return trimmed;
        }
        finally
        {
            resetStreamingState();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        requireInitialised();
        checkEncryptionReinit();
        // Size-check BEFORE buffering so a ShortBufferException leaves the
        // SPI state untouched — the JCE contract lets the caller retry with
        // a larger buffer and the SAME input, which must not double-buffer.
        int pendingLen = (input != null && inputLen > 0) ? inputLen : 0;
        int needed = engineGetOutputSize(pendingLen);
        if (output == null || output.length - outputOffset < needed)
        {
            throw new ShortBufferException(
                    "CCM output buffer too small: need " + needed +
                    " bytes from offset " + outputOffset);
        }
        if (input != null && inputLen > 0)
        {
            dataBuffer.write(input, inputOffset, inputLen);
        }
        try
        {
            int written;
            try
            {
                written = doFinalInternal(output, outputOffset);
            }
            catch (InvalidCipherTextException ex)
            {
                AEADBadTagException jceEx = new AEADBadTagException(ex.getMessage());
                jceEx.initCause(ex);
                throw jceEx;
            }
            // A successful encrypt consumes the nonce; block reuse until re-init.
            if (opMode == Cipher.ENCRYPT_MODE)
            {
                encryptionReinitRequired = true;
            }
            return written;
        }
        finally
        {
            resetStreamingState();
        }
    }


    /**
     * Hand the buffered AAD and data to the native one-shot
     * {@code ni_doFinal}.
     */
    private int doFinalInternal(byte[] output, int outputOffset)
            throws BadPaddingException
    {
        int aadLen = aadBuffer.size();
        byte[] aadBuf = (aadLen > 0) ? aadBuffer.getBuffer() : null;

        int dataLen = dataBuffer.size();
        byte[] dataBuf = dataBuffer.getBuffer();

        // synchronized(this) keeps the native ctx reachable across the
        // call (see engineInit). The java9 override uses
        // Reference.reachabilityFence(this) instead.
        synchronized (this)
        {
            return cipherNI.doFinal(ref.getReference(),
                    aadBuf, aadLen,
                    dataBuf, 0, dataLen,
                    output, outputOffset);
        }
    }


    /**
     * Throw if engineInit hasn't been called.
     */
    private void requireInitialised()
    {
        if (ref == null)
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    /**
     * Reject a second encryption on this instance without re-init —
     * reusing the nonce in CCM destroys confidentiality and authenticity.
     * Mirrors SunJCE's GCM "Cannot reuse iv" guard; decrypt is exempt.
     */
    private void checkEncryptionReinit()
    {
        if (opMode == Cipher.ENCRYPT_MODE && encryptionReinitRequired)
        {
            throw new IllegalStateException(
                    "CCM encryption cannot be reused with the same nonce; " +
                    "re-initialise with a fresh nonce before encrypting again");
        }
    }

    /**
     * Reset only the streaming buffers + AAD flag — opMode / iv / key
     * stay. A DECRYPT instance is immediately re-usable for another
     * doFinal without re-init. An ENCRYPT instance is NOT: the
     * encryptionReinitRequired guard (set after a successful encrypt)
     * forces re-init with a fresh nonce before encrypting again, since
     * reusing a CCM nonce is catastrophic (mirrors SunJCE's GCM guard).
     */
    private void resetStreamingState()
    {
        aadBuffer.reset();
        dataBuffer.reset();
        aadRejected = false;
    }

    private void disposeRef()
    {
        if (ref != null)
        {
            ref = null; // disposer chain handles native free
        }
    }


    // ----------------------------------------------------------------
    // Native lifecycle
    // ----------------------------------------------------------------

    protected static class Disposer extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            NISelector.CCMCipherNI.dispose(reference);
        }
    }

    protected static class CCMRef extends NativeReference
    {
        protected CCMRef(long reference, String name)
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
