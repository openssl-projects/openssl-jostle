/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Input-validation limit tests at the FIPS AES block-cipher NI surface
 * ({@link FIPSNISelector#BlockCipherNI}). The FIPS JNI glue is the base
 * block_cipher_ni_jni.c re-included under renamed symbols, so the bridge's
 * null/range/key-length checks are identical by construction — this pins
 * that they survived into the FIPS interface library and map to the same
 * typed exceptions + messages through the FIPS NI classes.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Discipline per
 * testing.md: exact-message assertions, key-length probed on both sides of
 * every valid length, every {@code int} offset/length fed {@code -1} and
 * {@code Integer.MIN_VALUE}, and the offset-write contract verified
 * functionally.
 */
public class FIPSBlockCipherLimitTest
{
    private static final int AES128 = OSSLCipher.AES128.ordinal();
    private static final int AES192 = OSSLCipher.AES192.ordinal();
    private static final int AES256 = OSSLCipher.AES256.ordinal();
    private static final int ECB = OSSLMode.ECB.ordinal();
    private static final int CBC = OSSLMode.CBC.ordinal();
    private static final int XTS = OSSLMode.XTS.ordinal();
    private static final int PKCS_PADDING = 1;
    private static final int NO_PADDING = 0;

    /** DES-EDE3 ordinals / block size, for the Triple-DES-specific tests. */
    private static final int DES_EDE3 = OSSLCipher.DES_EDE3.ordinal();
    private static final int CTR = OSSLMode.CTR.ordinal();
    private static final int DES_BLOCK = 8;

    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final BlockCipherNI ni = FIPSNISelector.BlockCipherNI;

    // ---------------------------------------------------------------------
    // init: key / iv / mode validation.
    // ---------------------------------------------------------------------

    @Test
    public void init_keyNull()
    {
        long ref = ni.makeInstance(AES128, CBC, PKCS_PADDING);
        try
        {
            Exception e = Assertions.assertThrows(Exception.class,
                    () -> ni.init(ref, Cipher.ENCRYPT_MODE, null, new byte[16], 0));
            Assertions.assertEquals("key is null", e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void init_modeTakesNoIv()
    {
        long ref = ni.makeInstance(AES128, ECB, PKCS_PADDING);
        try
        {
            Exception e = Assertions.assertThrows(Exception.class,
                    () -> ni.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0));
            Assertions.assertEquals("mode takes no iv", e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void init_ivNullOrEmptyForCbc()
    {
        for (byte[] iv : new byte[][]{null, new byte[0]})
        {
            long ref = ni.makeInstance(AES128, CBC, PKCS_PADDING);
            try
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.init(ref, Cipher.ENCRYPT_MODE, new byte[16], iv, 0),
                        "iv=" + (iv == null ? "null" : "empty"));
                Assertions.assertEquals("iv is null", e.getMessage());
            }
            finally
            {
                ni.dispose(ref);
            }
        }
    }

    @Test
    public void init_keyLengthBoundary()
    {
        // Valid lengths accepted; both neighbours of each rejected with the
        // exact class + message.
        assertInitKeyAccepted(AES128, 16);
        assertInitKeyAccepted(AES192, 24);
        assertInitKeyAccepted(AES256, 32);

        for (int len : new int[]{15, 17})
        {
            assertInitKeyRejected(AES128, len);
        }
        for (int len : new int[]{23, 25})
        {
            assertInitKeyRejected(AES192, len);
        }
        for (int len : new int[]{31, 33})
        {
            assertInitKeyRejected(AES256, len);
        }
        // A wildly wrong length is rejected too (guards an upper-bound-only check).
        assertInitKeyRejected(AES128, 64);
    }

    private void assertInitKeyAccepted(int cipher, int keyLen)
    {
        long ref = ni.makeInstance(cipher, ECB, PKCS_PADDING);
        try
        {
            ni.init(ref, Cipher.ENCRYPT_MODE, new byte[keyLen], null, 0);
        }
        catch (Exception e)
        {
            Assertions.fail("valid key length " + keyLen + " rejected: " + e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    private void assertInitKeyRejected(int cipher, int keyLen)
    {
        long ref = ni.makeInstance(cipher, ECB, PKCS_PADDING);
        try
        {
            ni.init(ref, Cipher.ENCRYPT_MODE, new byte[keyLen], null, 0);
            Assertions.fail("key length " + keyLen + " should be rejected");
        }
        catch (Exception e)
        {
            Assertions.assertEquals(InvalidKeyException.class, e.getClass(), "keyLen=" + keyLen);
            Assertions.assertEquals("invalid key length", e.getMessage(), "keyLen=" + keyLen);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // ---------------------------------------------------------------------
    // update: null / negative / range boundary.
    // ---------------------------------------------------------------------

    @Test
    public void update_inputNull()
    {
        withInitedCbc(ref ->
        {
            Exception e = Assertions.assertThrows(Exception.class,
                    () -> ni.update(ref, new byte[64], 0, null, 0, 0));
            Assertions.assertEquals("input is null", e.getMessage());
        });
    }

    @Test
    public void update_outputNull()
    {
        withInitedCbc(ref ->
        {
            Exception e = Assertions.assertThrows(Exception.class,
                    () -> ni.update(ref, null, 0, new byte[16], 0, 16));
            Assertions.assertEquals("output is null", e.getMessage());
        });
    }

    @Test
    public void update_outputOffsetNegative()
    {
        withInitedCbc(ref ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.update(ref, new byte[64], off, new byte[16], 0, 16), "off " + off);
                Assertions.assertEquals("output offset is negative", e.getMessage());
            }
        });
    }

    @Test
    public void update_inputOffsetNegative()
    {
        withInitedCbc(ref ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.update(ref, new byte[64], 0, new byte[16], off, 16), "off " + off);
                Assertions.assertEquals("input offset is negative", e.getMessage());
            }
        });
    }

    @Test
    public void update_inputLenNegative()
    {
        withInitedCbc(ref ->
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.update(ref, new byte[64], 0, new byte[16], 0, len), "len " + len);
                Assertions.assertEquals("input len is negative", e.getMessage());
            }
        });
    }

    @Test
    public void update_inputRangeBoundaryPlusOne()
    {
        withInitedCbc(ref ->
        {
            // 10-byte input buffer: len past end, then offset+len past end by one.
            Exception a = Assertions.assertThrows(Exception.class,
                    () -> ni.update(ref, new byte[64], 0, new byte[10], 0, 11));
            Assertions.assertEquals("input offset + length is out of range", a.getMessage());
            Exception b = Assertions.assertThrows(Exception.class,
                    () -> ni.update(ref, new byte[64], 0, new byte[10], 1, 10));
            Assertions.assertEquals("input offset + length is out of range", b.getMessage());
        });
    }

    // ---------------------------------------------------------------------
    // Offset-write contract, verified functionally (testing.md).
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        byte[] plaintext = new byte[16];   // one block; PKCS pads to 32
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(iv);
        RANDOM.nextBytes(plaintext);

        // Reference ciphertext at offset 0.
        byte[] reference = encryptCbc(key, iv, plaintext, 0, new byte[64]).clone();

        // Same encryption written at a non-zero offset into a random buffer.
        int prefix = 5;
        byte[] big = new byte[prefix + 64];
        RANDOM.nextBytes(big);
        byte[] savedPrefix = Arrays.copyOf(big, prefix);
        int written = encryptInto(key, iv, plaintext, big, prefix);

        // (1) prefix untouched.
        Assertions.assertArrayEquals(savedPrefix, Arrays.copyOf(big, prefix),
                "prefix region was clobbered");
        // (2) output region round-trips: decrypt it back to the plaintext.
        byte[] ct = Arrays.copyOfRange(big, prefix, prefix + written);
        Assertions.assertArrayEquals(plaintext, decryptCbc(key, iv, ct),
                "ciphertext written at offset does not decrypt to the plaintext");
        // (3) a window one byte earlier does NOT decrypt to the plaintext —
        //     proves the write landed at exactly `prefix`.
        byte[] shifted = Arrays.copyOfRange(big, prefix - 1, prefix - 1 + written);
        boolean shiftedRoundTrips;
        try
        {
            shiftedRoundTrips = Arrays.equals(plaintext, decryptCbc(key, iv, shifted));
        }
        catch (Exception decodeFailed)
        {
            shiftedRoundTrips = false; // padding/structure broke — also proves the shift
        }
        Assertions.assertFalse(shiftedRoundTrips, "ciphertext appears one byte before the offset");
    }

    // ---------------------------------------------------------------------
    // In-place / aliased-buffer operation (testing.md). AES CBC is a STREAMING
    // cipher: update/doFinal read and write incrementally, so the only
    // supported in-place layout is in == out at the SAME offset (each block is
    // read before its ciphertext is written back to the same location).
    // Partial overlap at DIFFERENT offsets is NOT an OpenSSL EVP contract —
    // a forward overlap (output ahead of input) has the write of ciphertext
    // block N clobber not-yet-read plaintext of block N+1, producing wrong
    // output. That corruption is platform-dependent (it surfaced only on a
    // Linux JNI critical-region direct pointer, not macOS), so different-offset
    // overlap is deliberately NOT tested here — testing it would codify UB.
    // Contrast the one-shot RSA ciphers, where partial overlap IS safe.
    // ---------------------------------------------------------------------

    @Test
    public void encrypt_inPlace_sameOffset() throws Exception
    {
        assertInPlaceSameOffsetCorrect();
    }

    /**
     * Encrypt with a single array serving as both input and output at the same
     * offset (0), and assert: (1) the written region equals the separate-buffer
     * reference, (2) it decrypts back to the plaintext, and (3) every byte of
     * the destination OUTSIDE the written region is byte-identical to a pre-call
     * snapshot — nothing accidentally clobbered.
     */
    private void assertInPlaceSameOffsetCorrect() throws Exception
    {
        int inOff = 0;
        int outOff = 0;
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        byte[] plaintext = new byte[32];   // two blocks; PKCS pads to 48
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(iv);
        RANDOM.nextBytes(plaintext);

        byte[] reference = encryptCbc(key, iv, plaintext, 0, new byte[64]);

        int cap = Math.max(inOff + plaintext.length, outOff + reference.length) + 16;
        byte[] buf = new byte[cap];
        RANDOM.nextBytes(buf);
        System.arraycopy(plaintext, 0, buf, inOff, plaintext.length);
        byte[] snapshot = buf.clone();   // includes the planted input

        int written;
        long ref = ni.makeInstance(AES256, CBC, PKCS_PADDING);
        try
        {
            ni.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0);
            int n = ni.update(ref, buf, outOff, buf, inOff, plaintext.length);
            n += ni.doFinal(ref, buf, outOff + n);
            written = n;
        }
        finally
        {
            ni.dispose(ref);
        }

        String where = "inOff=" + inOff + " outOff=" + outOff;
        Assertions.assertEquals(reference.length, written, where + " length");

        // (1) written region equals the separate-buffer reference.
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(buf, outOff, outOff + written),
                where + ": in-place output differs from separate-buffer reference");
        // (2) and round-trips back to the plaintext.
        Assertions.assertArrayEquals(plaintext,
                decryptCbc(key, iv, Arrays.copyOfRange(buf, outOff, outOff + written)),
                where + ": in-place ciphertext does not decrypt to the plaintext");
        // (3) WHOLE destination: everything outside the written region is
        //     byte-identical to the snapshot — nothing whacked.
        Assertions.assertArrayEquals(Arrays.copyOf(snapshot, outOff), Arrays.copyOf(buf, outOff),
                where + ": bytes before the output offset were clobbered");
        Assertions.assertArrayEquals(
                Arrays.copyOfRange(snapshot, outOff + written, cap),
                Arrays.copyOfRange(buf, outOff + written, cap),
                where + ": bytes after the written region were clobbered");
    }

    private int encryptInto(byte[] key, byte[] iv, byte[] pt, byte[] out, int outOff) throws Exception
    {
        long ref = ni.makeInstance(AES256, CBC, PKCS_PADDING);
        try
        {
            ni.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0);
            int n = ni.update(ref, out, outOff, pt, 0, pt.length);
            n += ni.doFinal(ref, out, outOff + n);
            return n;
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    private byte[] encryptCbc(byte[] key, byte[] iv, byte[] pt, int outOff, byte[] out) throws Exception
    {
        int n = encryptInto(key, iv, pt, out, outOff);
        return Arrays.copyOfRange(out, outOff, outOff + n);
    }

    private byte[] decryptCbc(byte[] key, byte[] iv, byte[] ct) throws Exception
    {
        long ref = ni.makeInstance(AES256, CBC, PKCS_PADDING);
        try
        {
            ni.init(ref, Cipher.DECRYPT_MODE, key, iv, 0);
            byte[] out = new byte[ct.length + 16];
            int n = ni.update(ref, out, 0, ct, 0, ct.length);
            n += ni.doFinal(ref, out, n);
            return Arrays.copyOf(out, n);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // ---------------------------------------------------------------------

    private interface RefBody
    {
        void run(long ref) throws Exception;
    }

    // ---------------------------------------------------------------------
    // XTS one-shot contract.
    //
    // The two guards live in the FIPS tree's own copy of block_cipher_ctx.c,
    // so the base BlockCipherLimitTest cannot vouch for them here — these pin
    // that they survived into the FIPS interface library.
    // ---------------------------------------------------------------------

    /**
     * XTS accumulates in util and hands EVP the whole data unit at final,
     * because EVP restarts the tweak sequence at the head of every update
     * call. Pinned against the FIPS library specifically — its util copy is a
     * separate source file, so the base test cannot vouch for it.
     */
    @Test
    public void xts_chunkedUpdatesAgreeWithOneShot() throws Exception
    {
        byte[] pt = new byte[64];
        for (int i = 0; i < pt.length; i++)
        {
            pt[i] = (byte) (i * 7 + 3);
        }

        byte[] oneShot = xtsEncryptChunked(pt, new int[]{64});

        for (int[] split : new int[][]{{32, 32}, {16, 16, 32}, {1, 63}, {63, 1}, {15, 17, 32}})
        {
            Assertions.assertArrayEquals(oneShot, xtsEncryptChunked(pt, split),
                    "split " + Arrays.toString(split) + " diverged from the one-shot result");
        }
    }

    /** Two sub-block chunks make a legal one-block data unit. */
    @Test
    public void xts_subBlockChunksAccumulate() throws Exception
    {
        long ref = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            Assertions.assertEquals(0, ni.init(ref, Cipher.ENCRYPT_MODE, xtsKey(), new byte[16], 0));
            byte[] out = new byte[16];
            Assertions.assertEquals(0, ni.update(ref, out, 0, new byte[16], 0, 8));
            Assertions.assertEquals(0, ni.update(ref, out, 0, new byte[16], 8, 8));
            Assertions.assertEquals(16, ni.doFinal(ref, out, 0));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    private byte[] xtsEncryptChunked(byte[] pt, int[] split) throws Exception
    {
        long ref = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            Assertions.assertEquals(0, ni.init(ref, Cipher.ENCRYPT_MODE, xtsKey(), new byte[16], 0));
            byte[] out = new byte[pt.length];
            int off = 0;
            for (int chunk : split)
            {
                Assertions.assertEquals(0, ni.update(ref, out, 0, pt, off, chunk),
                        "an XTS update must emit no bytes while accumulating");
                off += chunk;
            }
            Assertions.assertEquals(pt.length, ni.doFinal(ref, out, 0));
            return out;
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * A zero-length data unit reaches the native layer only through doFinal —
     * the SPI skips the update call when there is nothing to feed — so it
     * needs its own guard, and gets the same answer as the 1..15-byte case.
     */
    @Test
    public void xts_emptyDataUnitRejectedTyped() throws Exception
    {
        long ref = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            Assertions.assertEquals(0, ni.init(ref, Cipher.ENCRYPT_MODE, xtsKey(), new byte[16], 0));

            IllegalBlockSizeException e = Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> ni.doFinal(ref, new byte[16], 0));
            Assertions.assertEquals("data not block size aligned", e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * 15 bytes TOTAL refused, 16 accepted — the boundary sits at exactly one
     * block, and it is checked at final where the total is known rather than
     * per chunk (which would wrongly refuse 8 + 8).
     */
    @Test
    public void xts_subBlockDataUnitRejectedTyped() throws Exception
    {
        long ref = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            Assertions.assertEquals(0, ni.init(ref, Cipher.ENCRYPT_MODE, xtsKey(), new byte[16], 0));
            Assertions.assertEquals(0, ni.update(ref, new byte[16], 0, new byte[15], 0, 15));

            IllegalBlockSizeException e = Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> ni.doFinal(ref, new byte[16], 0));
            Assertions.assertEquals("data not block size aligned", e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }

        long okRef = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            Assertions.assertEquals(0, ni.init(okRef, Cipher.ENCRYPT_MODE, xtsKey(), new byte[16], 0));
            Assertions.assertEquals(0, ni.update(okRef, new byte[16], 0, new byte[16], 0, 16));
            Assertions.assertEquals(16, ni.doFinal(okRef, new byte[16], 0));
        }
        finally
        {
            ni.dispose(okRef);
        }
    }

    /** XTS refuses key1 == key2, so the two halves must differ. */
    private static byte[] xtsKey()
    {
        byte[] key = new byte[32];
        Arrays.fill(key, 0, 16, (byte) 0x11);
        Arrays.fill(key, 16, 32, (byte) 0x22);
        return key;
    }

    private void withInitedCbc(RefBody body)
    {
        long ref = ni.makeInstance(AES128, CBC, PKCS_PADDING);
        try
        {
            ni.init(ref, Cipher.ENCRYPT_MODE, new byte[16], new byte[16], 0);
            body.run(ref);
        }
        catch (Exception e)
        {
            if (e instanceof RuntimeException)
            {
                throw (RuntimeException) e;
            }
            throw new RuntimeException(e);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * Offset-write contract for XTS at the NI surface, four-step per
     * testing.md: random fill, snapshot the prefix, byte-compare it after the
     * call, then validate the written region functionally and prove a
     * one-byte-early window does NOT round-trip.
     */
    @Test
    public void testXts_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        byte[] key = xtsKey();
        byte[] tweak = new byte[16];
        byte[] pt = new byte[64];
        XTS_RANDOM.nextBytes(tweak);
        XTS_RANDOM.nextBytes(pt);

        byte[] reference = xtsEncrypt(key, tweak, pt, new byte[64], 0);

        final int prefix = 7;
        byte[] big = new byte[prefix + 64 + 9];
        XTS_RANDOM.nextBytes(big);
        byte[] savedPrefix = java.util.Arrays.copyOf(big, prefix);
        byte[] savedTail = java.util.Arrays.copyOfRange(big, prefix + 64, big.length);

        int written = xtsEncryptInto(key, tweak, pt, big, prefix);
        Assertions.assertEquals(64, written);

        Assertions.assertArrayEquals(savedPrefix, java.util.Arrays.copyOf(big, prefix),
                "prefix region was clobbered");
        Assertions.assertArrayEquals(savedTail,
                java.util.Arrays.copyOfRange(big, prefix + written, big.length),
                "bytes past the written region were clobbered");
        Assertions.assertArrayEquals(reference,
                java.util.Arrays.copyOfRange(big, prefix, prefix + written),
                "the region written at the offset is not the expected ciphertext");

        byte[] shifted = java.util.Arrays.copyOfRange(big, prefix - 1, prefix - 1 + written);
        Assertions.assertFalse(java.util.Arrays.equals(pt, xtsDecrypt(key, tweak, shifted)),
                "a window one byte early round-trips — the write landed before the offset");
    }

    /**
     * XTS reads its whole data unit before emitting output, but it is driven
     * through the streaming update/doFinal pair, so the supported aliased
     * layout is in == out at the SAME offset. Different-offset overlap is not
     * tested — see the note on the CBC in-place tests.
     */
    @Test
    public void testXts_inPlaceSameOffset() throws Exception
    {
        byte[] key = xtsKey();
        byte[] tweak = new byte[16];
        byte[] pt = new byte[64];
        XTS_RANDOM.nextBytes(tweak);
        XTS_RANDOM.nextBytes(pt);

        byte[] reference = xtsEncrypt(key, tweak, pt, new byte[64], 0);

        final int off = 5;
        byte[] buf = new byte[off + 64 + 11];
        XTS_RANDOM.nextBytes(buf);
        System.arraycopy(pt, 0, buf, off, pt.length);
        byte[] snapshot = buf.clone();

        int written = xtsEncryptInto(key, tweak, buf, off, pt.length, buf, off);
        Assertions.assertEquals(64, written);

        Assertions.assertArrayEquals(reference, java.util.Arrays.copyOfRange(buf, off, off + written),
                "in-place output differs from the separate-buffer reference");
        Assertions.assertArrayEquals(java.util.Arrays.copyOf(snapshot, off),
                java.util.Arrays.copyOf(buf, off), "bytes before the offset were clobbered");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, off + written, snapshot.length),
                java.util.Arrays.copyOfRange(buf, off + written, buf.length),
                "bytes after the written region were clobbered");
    }

    // --- XTS NI helpers ---

    private static final java.security.SecureRandom XTS_RANDOM = new java.security.SecureRandom();

    private byte[] xtsEncrypt(byte[] key, byte[] tweak, byte[] pt, byte[] out, int outOff) throws Exception
    {
        int n = xtsEncryptInto(key, tweak, pt, out, outOff);
        return java.util.Arrays.copyOfRange(out, outOff, outOff + n);
    }

    private int xtsEncryptInto(byte[] key, byte[] tweak, byte[] pt, byte[] out, int outOff) throws Exception
    {
        return xtsEncryptInto(key, tweak, pt, 0, pt.length, out, outOff);
    }

    private int xtsEncryptInto(byte[] key, byte[] tweak, byte[] in, int inOff, int inLen,
                               byte[] out, int outOff) throws Exception
    {
        long ref = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            ni.init(ref, Cipher.ENCRYPT_MODE, key, tweak, 0);
            int n = ni.update(ref, out, outOff, in, inOff, inLen);
            n += ni.doFinal(ref, out, outOff + n);
            return n;
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    private byte[] xtsDecrypt(byte[] key, byte[] tweak, byte[] ct) throws Exception
    {
        long ref = ni.makeInstance(AES128, XTS, NO_PADDING);
        try
        {
            ni.init(ref, Cipher.DECRYPT_MODE, key, tweak, 0);
            byte[] out = new byte[ct.length];
            int n = ni.update(ref, out, 0, ct, 0, ct.length);
            n += ni.doFinal(ref, out, n);
            return java.util.Arrays.copyOf(out, n);
        }
        finally
        {
            ni.dispose(ref);
        }
    }


    // ---------------------------------------------------------------------
    // DES-EDE3, the only registered cipher with an 8-byte block and a single
    // valid key length. Its arm of block_cipher_ctx_init carries three checks
    // of its own (24-byte key, 8-byte IV, ECB/CBC only) that no AES test can
    // reach. Every one of these drives DECRYPT: the checks are direction-
    // agnostic, and a module configured tdes-encrypt-disabled would otherwise
    // refuse the init before the check under test ran (testing.md, "gate the
    // narrowest thing").
    // ---------------------------------------------------------------------

    /** Skip unless the loaded module implements Triple-DES at all. */
    private static void assumeTripleDes()
    {
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesTripleDes(),
                "the loaded module does not implement Triple-DES");
    }

    @Test
    public void desEde3_keyLengthBoundaries()
    {
        assumeTripleDes();
        for (int len : new int[]{0, 1, 8, 15, 16, 17, 23, 25, 32})
        {
            long ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
            try
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.init(ref, Cipher.DECRYPT_MODE, new byte[len], new byte[DES_BLOCK], 0));
                Assertions.assertTrue(e instanceof InvalidKeyException, "type for len " + len);
                Assertions.assertEquals("invalid key length", e.getMessage());
            }
            finally
            {
                ni.dispose(ref);
            }
        }

        // Positive control: 24 bytes is accepted, so the check sits at exactly
        // the right place rather than rejecting everything.
        long ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
        try
        {
            Assertions.assertEquals(0,
                    ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], new byte[DES_BLOCK], 0));
        }
        catch (Exception e)
        {
            Assertions.fail("24-byte key must be accepted: " + e);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void desEde3_ivLengthBoundaries()
    {
        assumeTripleDes();
        // A zero-length array reaches the bridge indistinguishably from null
        // (load_bytearray_ctx reports size 0 either way), so it is the
        // null-IV code, not the length code — pinned separately rather than
        // folded into the loop, which is where the difference was found.
        for (byte[] iv : new byte[][]{null, new byte[0]})
        {
            long ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
            try
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], iv, 0));
                Assertions.assertTrue(e instanceof java.security.InvalidAlgorithmParameterException);
                Assertions.assertEquals("iv is null", e.getMessage());
            }
            finally
            {
                ni.dispose(ref);
            }
        }

        for (int len : new int[]{1, 7, 9, 16})
        {
            long ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
            try
            {
                Exception e = Assertions.assertThrows(Exception.class,
                        () -> ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], new byte[len], 0));
                Assertions.assertTrue(e instanceof java.security.InvalidAlgorithmParameterException,
                        "type for len " + len);
                Assertions.assertEquals("invalid iv length", e.getMessage());
            }
            finally
            {
                ni.dispose(ref);
            }
        }

        // Positive control: 8 bytes is accepted.
        long ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
        try
        {
            Assertions.assertEquals(0,
                    ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], new byte[DES_BLOCK], 0));
        }
        catch (Exception e)
        {
            Assertions.fail("8-byte IV must be accepted: " + e);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void desEde3_unsupportedModeRejectedTyped()
    {
        assumeTripleDes();
        // CTR is a legitimate OSSLMode and a legitimate DES-EDE3 mode in
        // OpenSSL's LEGACY provider, so it reaches the DES_EDE3 arm's
        // default: label rather than being screened out earlier.
        long ref = ni.makeInstance(DES_EDE3, CTR, NO_PADDING);
        try
        {
            Exception e = Assertions.assertThrows(Exception.class,
                    () -> ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], new byte[DES_BLOCK], 0));
            Assertions.assertTrue(e instanceof java.security.InvalidAlgorithmParameterException);
            Assertions.assertEquals("mode not supported for cipher", e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void desEde3_notBlockAlignedUsesEightNotSixteen() throws Exception
    {
        assumeTripleDes();
        // The 8-byte block is the point: 8 bytes must be ACCEPTED (it would be
        // refused for any 16-byte-block cipher) and 9 refused.
        long ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
        try
        {
            ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], new byte[DES_BLOCK], 0);
            Assertions.assertEquals(DES_BLOCK,
                    ni.update(ref, new byte[32], 0, new byte[DES_BLOCK], 0, DES_BLOCK),
                    "one 8-byte block must be accepted");
        }
        finally
        {
            ni.dispose(ref);
        }

        ref = ni.makeInstance(DES_EDE3, CBC, NO_PADDING);
        try
        {
            ni.init(ref, Cipher.DECRYPT_MODE, new byte[24], new byte[DES_BLOCK], 0);
            long r = ref;
            Exception e = Assertions.assertThrows(Exception.class,
                    () -> ni.update(r, new byte[32], 0, new byte[9], 0, 9));
            Assertions.assertTrue(e instanceof IllegalBlockSizeException);
            Assertions.assertEquals("data not block size aligned", e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }


}
