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
    private static final int PKCS_PADDING = 1;

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
    // In-place / aliased-buffer operation (testing.md): the FIPS AES block
    // cipher supports in == out at any layout (verified empirically); each
    // layout must equal the separate-buffer reference, round-trip, and leave
    // the ENTIRE destination outside the written region untouched.
    // ---------------------------------------------------------------------

    @Test
    public void encrypt_inPlace_sameOffset() throws Exception
    {
        assertInPlaceCorrect(0, 0);
    }

    @Test
    public void encrypt_inPlace_outputBelowInput() throws Exception
    {
        // Output starts before the input within one array (forward overlap).
        assertInPlaceCorrect(8, 0);
    }

    @Test
    public void encrypt_inPlace_outputAboveInput() throws Exception
    {
        // Output starts after the input within one array (backward overlap) —
        // the classic memcpy-should-be-memmove trap.
        assertInPlaceCorrect(0, 8);
    }

    /**
     * Encrypt with a single array serving as both input and output, input
     * planted at {@code inOff} and ciphertext written at {@code outOff}, and
     * assert: (1) the written region equals the separate-buffer reference,
     * (2) it decrypts back to the plaintext, and (3) every byte of the
     * destination OUTSIDE the written region is byte-identical to a pre-call
     * snapshot — nothing accidentally clobbered.
     */
    private void assertInPlaceCorrect(int inOff, int outOff) throws Exception
    {
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
}
