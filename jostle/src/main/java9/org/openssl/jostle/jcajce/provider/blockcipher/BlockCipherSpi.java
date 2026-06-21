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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.*;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.ref.Reference;
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
    int opMode;

    // IV / AEAD parameters in effect for the current init, retained so that
    // engineGetIV() and engineGetParameters() can report them — including IVs
    // this SPI generates itself when init is called without parameters (which
    // the JCE contract requires for encryption/wrapping, and which CMS relies
    // on to recover the content-encryption IV).
    private byte[] ivBytes;
    private int tagLen;

    // Nonce-reuse guard (mirrors SunJCE's GCM behaviour and CCMCipherSpi): set
    // true after a successful AEAD (GCM/OCB) encryption so any further data fed
    // to this instance — which would reuse the nonce, catastrophic for GCM/OCB —
    // is rejected until re-init establishes a fresh nonce.
    private boolean encryptionReinitRequired;

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
        // Seed the active osslMode field with the mandated mode. JCE
        // form-1 OID-alias lookup (e.g. Cipher.getInstance(some_oid))
        // resolves a primary that pre-locks the mode here and does NOT
        // call engineSetMode — without this assignment, ensureNativeReference
        // NPEs on osslMode.ordinal(). The shadowing of the field by
        // the same-named parameter is the reason this was easy to miss;
        // the explicit `this.` qualifier is intentional.
        this.osslMode = osslMode;
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

        if (osslMode == OSSLMode.CCM)
        {
            // CCM is one-shot (total length up-front, single AAD/payload
            // update) and does not fit this streaming SPI. It is only valid
            // via its dedicated transformation, e.g. "AES/CCM/NoPadding"
            // (AESCCMCipherSpi). Reject it here so a valid-format but
            // unregistered transformation (e.g. "AES/CCM/PKCS5Padding")
            // cannot fall through to this generic SPI and run CCM on the
            // wrong code path.
            throw new NoSuchAlgorithmException(
                    "CCM mode is only available via the dedicated <cipher>/CCM/NoPadding transformation");
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

    /**
     * SunJCE/CCMCipherSpi-style nonce-reuse guard for AEAD encryption. Once a
     * GCM/OCB encryption has completed, the nonce is spent; reject further data
     * input until the cipher is re-initialised (which draws a fresh nonce).
     */
    private void checkEncryptReuse()
    {
        if (encryptionReinitRequired)
        {
            throw new IllegalStateException(
                    osslMode + " encryption cannot be reused with the same nonce; re-initialise the cipher");
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        try
        {
            requireInitialized();

            // Block size is an algorithm invariant (independent of key/IV/init
            // state), so source it from the cipher descriptor rather than the
            // native EVP_CIPHER_CTX. Querying the context here during the
            // auto-IV branch of engineInit — before EVP_CipherInit_ex has run —
            // reported "not initialized" on a cold cache (CBC_AUTO_IV_COLD_CACHE_GAP.md).
            return osslCipher.getBlockSize();
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        try
        {
            requireInitialized();
            return blockCipherNi.getFinalSize(refWrapper.getReference(), inputLen);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineGetIV()
    {
        try
        {
            return Arrays.clone(ivBytes);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        try
        {
            if (ivBytes == null)
            {
                // ECB (and any mode initialised without an IV) carries no parameters.
                return null;
            }

            try
            {
                AlgorithmParameters params;
                if (isAeadMode())
                {
                    // GCM AlgorithmParameters is the de-facto JCE holder for any
                    // AEAD tag+nonce; OCB has no JCE-standard parameters type, so
                    // it reuses GCM's. The tag length is preserved on round-trip
                    // (a plain IvParameterSpec would drop it).
                    params = AlgorithmParameters.getInstance("GCM");
                    params.init(new GCMParameterSpec(tagLen * 8, ivBytes));
                }
                else
                {
                    params = AlgorithmParameters.getInstance(keyAlgorithm);
                    params.init(new IvParameterSpec(ivBytes));
                }
                return params;
            }
            catch (GeneralSecurityException e)
            {
                throw new IllegalStateException("unable to create AlgorithmParameters: " + e.getMessage(), e);
            }
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        // Delegate to the parameter-spec form with no parameters; for
        // encryption/wrapping it will generate any required IV/nonce itself.
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // No parameters were supplied and none could be generated (e.g. a
            // decrypt for a mode that requires an IV) — surface per JCE as an
            // InvalidKeyException for this entry point.
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }


    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        validateKeyAlg(key);
        try
        {
            ensureNativeReference();
            final byte[] iv;
            final int tag;
            // Associated data carried by a BC AEADParameterSpec, fed to the
            // native layer after a successful init (see below). Null otherwise.
            byte[] aeadAssociatedData = null;
            // The native layer only knows ENCRYPT/DECRYPT. WRAP/UNWRAP (used for
            // key-wrap modes) map onto encrypt/decrypt respectively.
            final int nativeOpMode = (opmode == Cipher.WRAP_MODE) ? Cipher.ENCRYPT_MODE
                : (opmode == Cipher.UNWRAP_MODE) ? Cipher.DECRYPT_MODE : opmode;
            this.opMode = nativeOpMode;

            if (params == null)
            {
                // No parameters supplied. For encryption/wrapping the JCE
                // contract is that the provider generates any required IV/nonce
                // at random; engineGetIV()/engineGetParameters() then expose it
                // so the recipient can decrypt. For decryption/unwrapping we
                // cannot invent the IV, so leave it null and let the native
                // layer reject the missing IV for modes that require one.
                int ivLen = (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) ? autoIvLength() : 0;
                if (ivLen > 0)
                {
                    iv = new byte[ivLen];
                    SecureRandom rng = (random != null) ? random : CryptoServicesRegistrar.getSecureRandom();
                    rng.nextBytes(iv);
                    tag = isAeadMode() ? 16 : 0;
                }
                else
                {
                    iv = null;
                    tag = 0;
                }
            }
            else if (isAeadMode() && AEADParameterSpecAccessor.matches(params))
            {
                // BC's AEADParameterSpec extends IvParameterSpec; unwrap it here,
                // BEFORE the IvParameterSpec branch, so its tag length and
                // associated data are honoured rather than silently dropped (the
                // dropped-AAD case produces a wrong-but-valid-looking tag).
                AEADParameterSpecAccessor acc = AEADParameterSpecAccessor.extract(params);
                int tLen = acc.getMacSizeInBits();
                if (tLen < 32 || tLen > 128 || (tLen & 7) != 0)
                {
                    throw new InvalidAlgorithmParameterException(
                            "AEAD tag length must be 32 to 128 bits and a multiple of 8");
                }
                iv = acc.getIV();
                tag = tLen / 8;
                aeadAssociatedData = acc.getAssociatedData();
            }
            else if (AEADParameterSpecAccessor.matches(params))
            {
                // AEAD-shaped spec on a non-AEAD mode: it cannot be honoured,
                // and letting it fall into the IvParameterSpec branch would
                // silently drop its tag length and associated data — exactly
                // the failure mode the accessor exists to prevent. BC rejects
                // this combination too.
                throw new InvalidAlgorithmParameterException(
                        "AEAD parameter spec cannot be used with non-AEAD mode " + osslMode);
            }
            else if (params instanceof IvParameterSpec)
            {
                iv = ((IvParameterSpec) params).getIV();
                tag = isAeadMode() ? 16 : 0;
            }
            else if (params instanceof GCMParameterSpec)
            {
                int tLen = ((GCMParameterSpec) params).getTLen();
                // Reject malformed AEAD tag lengths at the JCE boundary —
                // BouncyCastle's 32–128-bit, multiple-of-8 range, which the
                // cross-provider agreement tests rely on — rather than
                // passing an out-of-spec length down to OpenSSL.
                if (tLen < 32 || tLen > 128 || (tLen & 7) != 0)
                {
                    throw new InvalidAlgorithmParameterException(
                            "AEAD tag length must be 32 to 128 bits and a multiple of 8");
                }
                iv = ((GCMParameterSpec) params).getIV();
                tag = tLen / 8;
            }
            else
            {
                throw new InvalidAlgorithmParameterException("unsupported parameter spec: " + params);
            }

            this.ivBytes = iv;
            this.tagLen = tag;
            this.encryptionReinitRequired = false;

            byte[] keyBytes = key.getEncoded();
            try
            {
                blockCipherNi.init(refWrapper.getReference(), nativeOpMode, keyBytes, iv, tag);
            }
            finally
            {
                // Zeroize the plaintext key material once OpenSSL has copied it
                // into the EVP context. SecretKeySpec.getEncoded() returns a
                // fresh copy, so clearing it cannot corrupt the caller's key.
                if (keyBytes != null)
                {
                    Arrays.fill(keyBytes, (byte) 0);
                }
            }

            // Init succeeded: feed any AEADParameterSpec-supplied associated data
            // now — after init, before any plaintext — so it's authenticated.
            // This is the same native call engineUpdateAAD makes; the reuse guard
            // is unnecessary here because the cipher was just (re)initialised.
            if (aeadAssociatedData != null && aeadAssociatedData.length > 0)
            {
                blockCipherNi.updateAAD(refWrapper.getReference(), aeadAssociatedData, 0, aeadAssociatedData.length);
            }

            engineGetBlockSize();
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    /**
     * The IV/nonce length, in bytes, this mode needs when the caller supplies
     * no parameters. ECB and the key-wrap modes take none; GCM/OCB,
     * ChaCha20-Poly1305 (POLY1305), and raw ChaCha20 (STREAM) use a 12-byte
     * nonce; remaining block modes use the cipher's block size. Returns 0 when
     * no IV is required.
     */
    private int autoIvLength()
    {
        switch (osslMode)
        {
        case ECB:
        case WRAP:
        case WRAP_PAD:
            return 0;
        case GCM:
        case OCB:
        case POLY1305:
            return 12;
        case STREAM:
            // Raw ChaCha20 (RFC 8439) uses a 12-byte nonce; its block size is
            // 1, so the default branch would wrongly return 1.
            return 12;
        default:
            return engineGetBlockSize();
        }
    }

    /**
     * True for the AEAD modes this SPI drives (GCM, OCB, and ChaCha20-Poly1305's
     * synthetic POLY1305 mode). All append an
     * authentication tag and default to a 16-byte tag when the caller doesn't
     * specify one via a {@link GCMParameterSpec}. CCM is handled by a dedicated
     * SPI and is not seen here. The default-16 applies to OCB as well as GCM:
     * leaving OCB's tag length at 0 left OpenSSL's OCB cipher with no tag length
     * established, which surfaced as {@code aes_ocb_get_ctx_params: invalid tag
     * length} at the {@code EVP_CTRL_AEAD_GET_TAG} step on encrypt.
     */
    private boolean isAeadMode()
    {
        return osslMode == OSSLMode.GCM || osslMode == OSSLMode.OCB || osslMode == OSSLMode.POLY1305;
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
        try
        {
            requireInitialized();
            checkEncryptReuse();
            blockCipherNi.updateAAD(refWrapper.getReference(), src, offset, len);
        }
        finally
        {
            Reference.reachabilityFence(this);
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
        try
        {
            requireInitialized();
            checkEncryptReuse();
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
        finally
        {
            Reference.reachabilityFence(this);
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
        try
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
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException
    {
        try
        {
            requireInitialized();
            checkEncryptReuse();
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
            } catch (IllegalBlockSizeException ibsx) {
                throw new RuntimeException(ibsx.getMessage(),ibsx);
            }

        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException
    {
        try
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
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {

        try
        {
            requireInitialized();
            checkEncryptReuse();
            int k = blockCipherNi.getFinalSize(refWrapper.getReference(), inputLen);

            if (outputOffset + k > output.length)
            {
                throw new ShortBufferException("output buffer too small");
            }


            byte[] workingInput = input;


            if (input != null && input == output) // same array
            {
                if (overlap(inputOffset, inputLen, outputOffset, k))
                {
                    workingInput = new byte[inputLen];
                    System.arraycopy(input, inputOffset, workingInput, 0, inputLen);
                    inputOffset = 0;
                }
            }


            int written = 0;

            // Cipher.doFinal() (no-args) lands here with input=null,
            // inputLen=0. Skip the NI.update call entirely — the EVP
            // layer treats a zero-length update as a no-op, but the
            // NI bridge null-checks workingInput up front and would
            // throw NullPointerException. Only call update when there
            // are bytes to feed.
            if (inputLen > 0)
            {
                written += blockCipherNi.update(refWrapper.getReference(), output, outputOffset, workingInput, inputOffset, inputLen);
            }

            int code = blockCipherNi.doFinal(refWrapper.getReference(), output, outputOffset + written);

            written += code;

            if (opMode == Cipher.ENCRYPT_MODE && (osslMode == OSSLMode.GCM || osslMode == OSSLMode.OCB || osslMode == OSSLMode.POLY1305))
            {
                // A successful AEAD encryption consumes the nonce; block reuse until re-init.
                encryptionReinitRequired = true;
            }

            return written;
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0)
        {
            throw new InvalidKeyException("cannot wrap key with null or empty encoding");
        }
        try
        {
            return engineDoFinal(encoded, 0, encoded.length);
        }
        catch (BadPaddingException e)
        {
            // wrapping is an encryption operation; a padding error is not expected.
            throw new IllegalBlockSizeException(e.getMessage());
        }
        finally
        {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        final byte[] encoded;
        try
        {
            encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new InvalidKeyException("unable to unwrap key: " + e.getMessage(), e);
        }

        try
        {
            switch (wrappedKeyType)
            {
            case Cipher.SECRET_KEY:
                return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
            case Cipher.PUBLIC_KEY:
                return KeyFactory.getInstance(wrappedKeyAlgorithm).generatePublic(new X509EncodedKeySpec(encoded));
            case Cipher.PRIVATE_KEY:
                return KeyFactory.getInstance(wrappedKeyAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(encoded));
            default:
                throw new InvalidKeyException("unknown wrapped key type: " + wrappedKeyType);
            }
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException("unable to reconstruct unwrapped key: " + e.getMessage(), e);
        }
        finally
        {
            // SecretKeySpec / the key specs copy the bytes, so clear our copy.
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Ensure a valid native reference
     */
    protected void ensureNativeReference()
    {
        try
        {
            if (refWrapper == null)
            {
                long ref = blockCipherNi.makeInstance(osslCipher.ordinal(), osslMode.ordinal(), padding);
                refWrapper = new OSSLBlockCipherRefWrapper(ref, osslCipher.name());
            }
        }
        finally
        {
            Reference.reachabilityFence(this);
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
        // A password/KDF-derived key (PBKDF2 or scrypt — a javax.crypto PBEKey)
        // is generic RAW key material whose owning algorithm is the PBES2 /
        // PKCS#8 EncryptionScheme, not a competing cipher; accept it for any
        // cipher (the native layer still validates the key length). A key
        // explicitly tagged for a different cipher family — e.g. an "ARIA"
        // SecretKeySpec on an AES cipher — is not a PBEKey and is still rejected
        // by the name check below.
        if (key instanceof PBEKey)
        {
            return;
        }

        String alg = key.getAlgorithm();
        if (alg != null)
        {
            String a = Strings.toUpperCase(alg);
            String expected = Strings.toUpperCase(keyAlgorithm);
            // Accept the cipher's own key algorithm, and the JCE key-wrap
            // spellings of it whose key material is still an <alg> key — e.g.
            // "AES" also matches "AESWrap"/"AESWRAP"/"AESKW". A CEK recovered via
            // a key-wrap Cipher.unwrap(...) is commonly tagged with the wrap name
            // rather than the bare cipher name (notably on the CMS KEM/KTS
            // recipient path, RFC 9629), so a strict equals would reject it. A
            // genuinely different algorithm (e.g. "ARIA" for an AES cipher) does
            // not share the prefix and is still rejected; key length is validated
            // by the native layer regardless.
            if (a.equals(expected) || a.startsWith(expected))
            {
                return;
            }
            // A content-encryption key recovered from a CMS structure (e.g. the
            // CEK unwrapped on a KeyAgreeRecipientInfo / KeyTransRecipientInfo
            // path) is tagged with the content algorithm OID, not the bare
            // cipher name — an AES-128-GCM CEK arrives as "2.16.840.1.101.3.4.1.6".
            // Accept an OID under this cipher family's arc; a foreign family's
            // OID does not match, so the cross-algorithm guard is preserved and
            // the native layer still validates key length.
            if (isContentOidForFamily(alg))
            {
                return;
            }
        }
        throw new InvalidKeyException("unsupported key algorithm " + alg);
    }

    /**
     * True when {@code alg} is a content-encryption algorithm OID belonging to
     * this cipher's family — the form a CMS CEK is tagged with. Currently only
     * the NIST AES arc ({@code 2.16.840.1.101.3.4.1.*}) is recognised, which is
     * the dominant CMS content cipher; other families fall through to the name
     * check and are unaffected.
     */
    private boolean isContentOidForFamily(String alg)
    {
        if ("AES".equalsIgnoreCase(keyAlgorithm))
        {
            return alg.startsWith("2.16.840.1.101.3.4.1.");
        }
        return false;
    }

}
