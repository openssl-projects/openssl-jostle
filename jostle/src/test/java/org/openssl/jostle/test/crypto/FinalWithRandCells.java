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

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import java.security.SecureRandom;

/**
 * Limit cells for the block cipher final that carries a RandSource, shared by the base and FIPS limit tests: on a
 * mode that draws nothing at its final it behaves exactly as the plain final, and its bridge checks are typed.
 */
public final class FinalWithRandCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private FinalWithRandCells()
    {
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    /** An AES-128 CBC encrypt with the PKCS#7 padding, initialised and fed, ready for its final. */
    private static long fedCbc(BlockCipherNI ni, byte[] key, byte[] iv, byte[] msg) throws Exception
    {
        long ref = ni.makeInstance(OSSLCipher.AES128.ordinal(), OSSLMode.CBC.ordinal(), 1);
        ni.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0);
        int n = ni.update(ref, new byte[msg.length + 16], 0, msg, 0, msg.length);
        Assertions.assertTrue(n >= 0);
        return ref;
    }

    /** On a mode that draws nothing at its final, the RandSource final gives the plain final's bytes and code. */
    public static void aModeThatDrawsNothingFinalisesIdentically(BlockCipherNI ni) throws Exception
    {
        byte[] key = random(16);
        byte[] iv = random(16);
        byte[] msg = random(5 + RANDOM.nextInt(40));
        long plain = fedCbc(ni, key, iv, msg);
        long withRand = fedCbc(ni, key, iv, msg);
        try
        {
            byte[] a = new byte[64];
            byte[] b = new byte[64];
            int na = ni.ni_doFinal(plain, a, 3);
            int nb = ni.ni_doFinalWithRand(withRand, b, 3, TestUtil.RNDSrc);
            Assertions.assertEquals(na, nb);
            Assertions.assertTrue(na > 0);
            Assertions.assertArrayEquals(a, b);
        }
        finally
        {
            ni.dispose(plain);
            ni.dispose(withRand);
        }
    }

    /** The bridge refuses a null handle, a null RandSource, a null output and out-of-range offsets, typed. */
    public static void bridgeChecksAreTyped(BlockCipherNI ni) throws Exception
    {
        byte[] out = new byte[32];
        Assertions.assertEquals(ni.ni_doFinal(0, out, 0), ni.ni_doFinalWithRand(0, out, 0, TestUtil.RNDSrc),
                "a null handle is refused as the plain final refuses it");
        Assertions.assertTrue(ni.ni_doFinalWithRand(0, out, 0, TestUtil.RNDSrc) < 0);

        long ref = fedCbc(ni, random(16), random(16), random(16));
        try
        {
            Assertions.assertEquals(ErrorCode.JO_RAND_NO_RAND_UP_CALL.getCode(),
                    ni.ni_doFinalWithRand(ref, out, 0, null));
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_IS_NULL.getCode(),
                    ni.ni_doFinalWithRand(ref, null, 0, TestUtil.RNDSrc));
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OFFSET_IS_NEGATIVE.getCode(),
                    ni.ni_doFinalWithRand(ref, out, -1, TestUtil.RNDSrc));
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OFFSET_IS_NEGATIVE.getCode(),
                    ni.ni_doFinalWithRand(ref, out, Integer.MIN_VALUE, TestUtil.RNDSrc));
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OUT_OF_RANGE.getCode(),
                    ni.ni_doFinalWithRand(ref, out, out.length + 1, TestUtil.RNDSrc));
            // The offset at the end is in range and leaves no room, which the util layer refuses.
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_SMALL.getCode(),
                    ni.ni_doFinalWithRand(ref, out, out.length, TestUtil.RNDSrc));
            // Nothing was consumed by the refusals: the final still completes, writing the padding block (the
            // 16-byte message itself was emitted by update).
            Assertions.assertEquals(16, ni.ni_doFinalWithRand(ref, out, 0, TestUtil.RNDSrc));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * RFC 3217's wrap draws its IV at the final: the plain final refuses it typed and consumes nothing, so the
     * RandSource final then completes the same wrap. The unwrap draws nothing and the plain final serves it.
     */
    public static void desedeWrapNeedsTheRandSourceFinal(BlockCipherNI ni) throws Exception
    {
        byte[] kek = random(24);
        byte[] cek = random(24);
        long wrap = ni.makeInstance(OSSLCipher.DES_EDE3.ordinal(), OSSLMode.WRAP.ordinal(), 0);
        long unwrap = ni.makeInstance(OSSLCipher.DES_EDE3.ordinal(), OSSLMode.WRAP.ordinal(), 0);
        try
        {
            ni.init(wrap, Cipher.ENCRYPT_MODE, kek, null, 0);
            Assertions.assertEquals(0, ni.update(wrap, new byte[40], 0, cek, 0, cek.length));
            byte[] blob = new byte[40];
            Assertions.assertEquals(ErrorCode.JO_RAND_SOURCE_REQUIRED.getCode(), ni.ni_doFinal(wrap, blob, 0));
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> ni.doFinal(wrap, blob, 0));
            Assertions.assertEquals("this mode draws random bytes at its final step and needs a random source",
                    e.getMessage());
            Assertions.assertEquals(40, ni.ni_doFinalWithRand(wrap, blob, 0, TestUtil.RNDSrc));

            ni.init(unwrap, Cipher.DECRYPT_MODE, kek, null, 0);
            Assertions.assertEquals(0, ni.update(unwrap, new byte[40], 0, blob, 0, blob.length));
            byte[] recovered = new byte[40];
            Assertions.assertEquals(24, ni.ni_doFinal(unwrap, recovered, 0));
            Assertions.assertArrayEquals(cek, Arrays.copyOfRange(recovered, 0, 24));
        }
        finally
        {
            ni.dispose(wrap);
            ni.dispose(unwrap);
        }
    }

    /** A SecureRandom that counts the bytes it serves. */
    private static final class Counting extends SecureRandom
    {
        int served;

        @Override
        public void nextBytes(byte[] out)
        {
            super.nextBytes(out);
            served += out.length;
        }
    }

    /**
     * A Triple-DES wrap refused for a short output draws nothing and keeps its input; the retry with room
     * completes with one 8-byte draw and a blob that unwraps to the key.
     */
    public static void desedeWrapShortBufferRetryDrawsOnce(BlockCipherNI ni) throws Exception
    {
        byte[] kek = random(24);
        byte[] cek = random(24);
        Counting counting = new Counting();
        RandSource rand = DefaultRandSource.wrap(counting);
        long wrap = ni.makeInstance(OSSLCipher.DES_EDE3.ordinal(), OSSLMode.WRAP.ordinal(), 0);
        long unwrap = ni.makeInstance(OSSLCipher.DES_EDE3.ordinal(), OSSLMode.WRAP.ordinal(), 0);
        try
        {
            ni.init(wrap, Cipher.ENCRYPT_MODE, kek, null, 0);
            Assertions.assertEquals(0, ni.update(wrap, new byte[40], 0, cek, 0, cek.length));
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_SMALL.getCode(),
                    ni.ni_doFinalWithRand(wrap, new byte[39], 0, rand));
            Assertions.assertEquals(0, counting.served, "the refused call drew nothing");
            byte[] blob = new byte[40];
            Assertions.assertEquals(40, ni.ni_doFinalWithRand(wrap, blob, 0, rand));
            Assertions.assertEquals(8, counting.served, "the retry drew the IV once");

            ni.init(unwrap, Cipher.DECRYPT_MODE, kek, null, 0);
            Assertions.assertEquals(0, ni.update(unwrap, new byte[40], 0, blob, 0, blob.length));
            byte[] recovered = new byte[40];
            Assertions.assertEquals(24, ni.ni_doFinalWithRand(unwrap, recovered, 0, rand));
            Assertions.assertArrayEquals(cek, Arrays.copyOfRange(recovered, 0, 24));
            Assertions.assertEquals(8, counting.served, "unwrap drew nothing");
        }
        finally
        {
            ni.dispose(wrap);
            ni.dispose(unwrap);
        }
    }
}
