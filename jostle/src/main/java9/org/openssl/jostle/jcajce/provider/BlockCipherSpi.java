/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.lang.ref.Reference;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;


class BlockCipherSpi extends CipherSpi
{
    final OSSLCipher mandatedCipher;
    final OSSLMode mandatedMode;
    OSSLCipher osslCipher;
    OSSLMode osslMode;
    int padding;
    OSSLBlockCipherRefWrapper refWrapper;
    int blockSize;
    int opMode;
    final String keyAlgorithm;

    private static int BUF_SIZE = 1024;

    Class[] availableSpecs = new Class[]{
            IvParameterSpec.class,
            GCMParameterSpec.class,
    };

    BlockCipherSpi(Object params, String keyAlgorithm)
    {
        mandatedCipher = null;
        mandatedMode = null;
        this.keyAlgorithm = keyAlgorithm;
    }

    BlockCipherSpi(OSSLCipher osslCipher, String keyAlgorithm)
    {
        mandatedCipher = osslCipher;
        mandatedMode = null;
        this.keyAlgorithm = keyAlgorithm;
    }

    BlockCipherSpi(OSSLCipher osslCipher, OSSLMode osslMode, String keyAlgorithm)
    {
        mandatedCipher = osslCipher;
        mandatedMode = osslMode;
        this.keyAlgorithm = keyAlgorithm;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        osslMode = OSSLMode.valueOf(mode);

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
        } else if (padding.equals("PKCS7PADDING") || padding.equals("PKCS5PADDING"))
        {
            this.padding = 1;
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        try
        {
            if (refWrapper == null)
            {
                throw new IllegalStateException("cipher not initialized");
            }

            if (blockSize == 0)
            {
                blockSize = NISelector.BlockCipherNI.getBlockSize(refWrapper.getReference());
            }

            return blockSize;
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        try
        {
            return NISelector.BlockCipherNI.getFinalSize(refWrapper.getReference(), inputLen);
        } finally
        {
            Reference.reachabilityFence(this);
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

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        validateKeyAlg(key);
        try
        {
            ensureNativeReference();

            blockSize = 0;
            this.opMode = opmode;

            byte[] keyBytes = key.getEncoded();
            ErrorCode codes = ErrorCode.forCode(() -> NISelector.BlockCipherNI.init(refWrapper.getReference(), opmode, keyBytes, null, 0));
            try
            {
                BlockCipherNI.handleInitErrorCodes(codes, keyBytes.length, 0);
            } catch (InvalidAlgorithmParameterException e)
            {
                throw new InvalidKeyException(e.getMessage());
            }
            engineGetBlockSize();
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        validateKeyAlg(key);
        try
        {
            ensureNativeReference();
            byte[] keyBytes = key.getEncoded();
            ErrorCode codes;
            final byte[] ivBytes;
            int tagLen;
            blockSize = 0;
            this.opMode = opmode;

            if (params == null)
            {
                ivBytes = null;
                tagLen = 0;
            } else if (params instanceof IvParameterSpec)
            {
                ivBytes = ((IvParameterSpec) params).getIV();
                if (osslMode == OSSLMode.GCM)
                {
                    tagLen = 16;
                } else
                {
                    tagLen = 0;
                }

            } else if (params instanceof GCMParameterSpec)
            {
                ivBytes = ((GCMParameterSpec) params).getIV();
                tagLen = (((GCMParameterSpec) params).getTLen() + 7) / 8;
            } else
            {
                throw new InvalidAlgorithmParameterException("unsupported parameter spec: " + params);
            }

            codes = ErrorCode.forCode(() -> NISelector.BlockCipherNI.init(refWrapper.getReference(), opmode, keyBytes, ivBytes, tagLen));
            BlockCipherNI.handleInitErrorCodes(codes, keyBytes.length, ivBytes == null ? 0 : ivBytes.length);


            engineGetBlockSize();
        } finally
        {
            Reference.reachabilityFence(this);
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
                } catch (Exception e)
                {
                    // try next spec
                }
            }

            if (paramSpec == null)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }


        // TODO deal
        engineInit(opmode, key, paramSpec, random);


        //throw new IllegalStateException("Not implemented");
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len)
    {

        try
        {
            len = NISelector.BlockCipherNI.updateAAD(
                    refWrapper.getReference(),
                    src, offset, len);

            try
            {
                BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(len));
            } catch (IllegalBlockSizeException | ShortBufferException ibe)
            {
                throw new RuntimeException(ibe.getMessage(), ibe);
            }

        } finally
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
        } else if (src.hasArray())
        {
            engineUpdateAAD(src.array(), src.arrayOffset() + src.position(), remaining);
            src.position(src.limit());
        } else if (remaining <= BUF_SIZE)
        {
            byte[] data = new byte[remaining];
            src.get(data);
            engineUpdateAAD(data, 0, data.length);
            Arrays.fill(data, (byte) 0);
        } else
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


    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        try
        {
            int len = NISelector.BlockCipherNI.getUpdateSize(refWrapper.getReference(), inputLen);
            byte[] output = new byte[len];

            len = NISelector.BlockCipherNI.update(
                    refWrapper.getReference(),
                    output,
                    0,
                    input,
                    inputOffset, inputLen);

            try
            {
                BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(len));
            } catch (IllegalBlockSizeException | ShortBufferException ibe)
            {
                throw new RuntimeException(ibe.getMessage(), ibe);
            }


            return output.length == len ? output : Arrays.copyOf(output, len);
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }


    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException
    {
        try
        {
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


            int len = NISelector.BlockCipherNI.update(
                    refWrapper.getReference(),
                    output,
                    outputOffset,
                    workingInput,
                    inputOffset,
                    inputLen);

            try
            {
                BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(len));
            } catch (IllegalBlockSizeException ibe)
            {
                throw new RuntimeException(ibe.getMessage(), ibe);
            }

            return len;

        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException
    {
        try
        {
            int len = NISelector.BlockCipherNI.getFinalSize(refWrapper.getReference(), inputLen);
            byte[] output = new byte[len];
            try
            {
                int written = engineDoFinal(input, inputOffset, inputLen, output, 0);
                return written == output.length ? output : Arrays.copyOf(output, written);
            } catch (ShortBufferException sbe)
            {
                throw new IllegalBlockSizeException(sbe.getMessage());
            }
        } finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {

        try
        {
            int k = NISelector.BlockCipherNI.getFinalSize(refWrapper.getReference(), inputLen);

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
            int code = NISelector.BlockCipherNI.update(refWrapper.getReference(), output, outputOffset, workingInput, inputOffset, inputLen);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));
            written += code;

            code = NISelector.BlockCipherNI.doFinal(refWrapper.getReference(), output, outputOffset + written);
            BlockCipherNI.handleFinalErrorCodes(ErrorCode.forCode(code));

            written += code;
            return written;
        } finally
        {
            Reference.reachabilityFence(this);
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
                long ref = NISelector.BlockCipherNI.makeInstance(osslCipher.ordinal(), osslMode.ordinal(), padding);
                if (ref == 0)
                {
                    throw new IllegalStateException("Unable to create: " + osslCipher.name() + " " + osslMode.name());
                }
                refWrapper = new OSSLBlockCipherRefWrapper(ref, osslCipher.name());
            }
        } finally
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
            NISelector.BlockCipherNI.dispose(reference);
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
            return new Disposer(reference);
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
