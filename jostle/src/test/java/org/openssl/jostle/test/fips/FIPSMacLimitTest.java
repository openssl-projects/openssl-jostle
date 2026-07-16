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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Input-validation limit tests at the FIPS MAC NI surface
 * ({@link FIPSNISelector#MacServiceNI}). The FIPS JNI glue is the base
 * mac_ni_jni.c re-included under renamed symbols, so the bridge's
 * null/range/key-length checks and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same JO_* codes and messages.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 *
 * <p>FIPS divergence from the base {@code MacLimitTest}: Poly1305 is NOT a
 * FIPS-approved MAC, so {@code allocateMac("POLY1305", ...)} fails the fetch
 * under the FIPS lib ctx (see {@link #poly1305_notFipsApproved()}). The base
 * test uses Poly1305 to exercise the "invalid key length for mac type" branch;
 * here CMAC-AES (which is approved) exercises the same branch.
 *
 * <p>Discipline (testing.md): exact-message assertions, every {@code int}
 * offset/length fed {@code -1} AND {@code Integer.MIN_VALUE}, range checks
 * probed at exactly {@code boundary + 1}, and the offset-write contract
 * verified functionally against a reference MAC.
 */
public class FIPSMacLimitTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final MacServiceNI macNI = FIPSNISelector.MacServiceNI;

    // ---------------------------------------------------------------------
    // allocateMac: name validation + FIPS-approval boundary.
    // ---------------------------------------------------------------------

    @Test
    public void allocateMac_macNameNull()
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                () -> macNI.allocateMac(null, "cats"));
        Assertions.assertEquals("name is null", e.getMessage());
    }

    @Test
    public void allocateMac_functionNameNull()
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                () -> macNI.allocateMac("HMAC", null));
        Assertions.assertEquals("mac function name is null", e.getMessage());
    }

    @Test
    public void allocateMac_unknownAlgorithm()
    {
        // EVP_MAC_fetch fails -> JO_OPENSSL_ERROR -> OpenSSLException. Message
        // is OpenSSL-version dependent, so prefix-match per testing.md.
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                () -> macNI.allocateMac("ZZZZZZZ", "SHA-256"));
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
    }

    @Test
    public void poly1305_notFipsApproved()
    {
        // Poly1305 is not in the FIPS provider; the fetch under the FIPS lib
        // ctx fails as "unsupported". This is a genuine FIPS distinction from
        // the base MacLimitTest, where Poly1305 is available.
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                () -> macNI.allocateMac("POLY1305", "POLY1305"));
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:")
                && e.getMessage().contains("POLY1305"), e.getMessage());
    }

    // ---------------------------------------------------------------------
    // init: key validation.
    // ---------------------------------------------------------------------

    @Test
    public void init_keyNull()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> macNI.engineInit(ref, null));
            Assertions.assertEquals("key is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void init_emptyKey() throws Exception
    {
        // The native layer accepts a zero-length HMAC key (SecretKeySpec would
        // not, but that guard lives above the NI).
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[0]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void init_reInitDifferentKey() throws Exception
    {
        // Exercises mac_init's alias-safe re-init across three key lengths.
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineInit(ref, new byte[32]);
            macNI.engineInit(ref, new byte[64]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void cmac_invalidKeyLen()
    {
        // CMAC-AES accepts 16/24/32; 17 hits the "invalid key length for mac
        // type" branch (JO_UNKNOWN_KEY_LEN) — the same branch the base test
        // reaches via Poly1305, which is unavailable under FIPS.
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> macNI.engineInit(ref, new byte[17]));
            Assertions.assertEquals("invalid key length for mac type", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void cmac_unknownCipher()
    {
        // des-cbc is not available under the FIPS lib ctx; the cipher fetch at
        // init fails and surfaces as "unexpected state".
        long ref = macNI.allocateMac("CMAC", "des-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> macNI.engineInit(ref, new byte[16]));
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    // ---------------------------------------------------------------------
    // update: null / negative / range boundary / not-initialised.
    // ---------------------------------------------------------------------

    @Test
    public void update_inputNull()
    {
        withInitedHmac(ref ->
        {
            NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                    () -> macNI.engineUpdate(ref, null, 0, 0));
            Assertions.assertEquals("input is null", e.getMessage());
        });
    }

    @Test
    public void update_inputOffsetNegative()
    {
        withInitedHmac(ref ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> macNI.engineUpdate(ref, new byte[1], off, 1), "off " + off);
                Assertions.assertEquals("input offset is negative", e.getMessage());
            }
        });
    }

    @Test
    public void update_inputLenNegative()
    {
        withInitedHmac(ref ->
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> macNI.engineUpdate(ref, new byte[1], 0, len), "len " + len);
                Assertions.assertEquals("input len is negative", e.getMessage());
            }
        });
    }

    @Test
    public void update_inputRangeBoundaryPlusOne()
    {
        withInitedHmac(ref ->
        {
            // 10-byte buffer: len past end, offset+len past end by one, offset
            // itself past end. Positive-side companion: offset==length, len 0.
            assertUpdateOutOfRange(ref, 10, 0, 11);   // 0 + 11 = 11 > 10
            assertUpdateOutOfRange(ref, 10, 1, 10);   // 1 + 10 = 11 > 10
            assertUpdateOutOfRange(ref, 10, 11, 21);  // offset itself past end
            macNI.engineUpdate(ref, new byte[10], 10, 0);
            macNI.engineUpdate(ref, new byte[10], 0, 10);
        });
    }

    private void assertUpdateOutOfRange(long ref, int size, int off, int len)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineUpdate(ref, new byte[size], off, len),
                "size=" + size + " off=" + off + " len=" + len);
        Assertions.assertEquals("input offset + length is out of range", e.getMessage());
    }

    @Test
    public void update_notInitialised_array()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> macNI.engineUpdate(ref, new byte[32], 0, 32));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_notInitialised_byte()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> macNI.engineUpdate(ref, (byte) 1));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    // ---------------------------------------------------------------------
    // doFinal: null / negative / too-small / not-initialised.
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_outputNull()
    {
        withInitedHmac(ref ->
        {
            NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                    () -> macNI.doFinal(ref, null, 0));
            Assertions.assertEquals("output is null", e.getMessage());
        });
    }

    @Test
    public void doFinal_outputOffsetNegative()
    {
        withInitedHmac(ref ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> macNI.doFinal(ref, new byte[32], off), "off " + off);
                Assertions.assertEquals("output offset is negative", e.getMessage());
            }
        });
    }

    @Test
    public void doFinal_outputTooSmall() throws Exception
    {
        // HMAC-SHA512 produces 64 bytes; offset 1 into a 32-byte buffer
        // (1 + 64 = 65 > 32) is the smallest out-of-range write here.
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> macNI.doFinal(ref, new byte[32], 1));
            Assertions.assertEquals("output offset + mac len is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> macNI.doFinal(ref, new byte[64], 0));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    // ---------------------------------------------------------------------
    // Offset-write contract for doFinal, verified functionally against a
    // reference MAC (testing.md). MAC is deterministic, so the written region
    // must equal the reference byte-for-byte.
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        byte[] key = new byte[32];
        byte[] input = new byte[64 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(input);

        // Reference HMAC-SHA256 at offset 0.
        byte[] reference = new byte[32];
        long refA = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(refA, key);
            macNI.engineUpdate(refA, input, 0, input.length);
            Assertions.assertEquals(32, macNI.doFinal(refA, reference, 0));
        }
        finally
        {
            macNI.dispose(refA);
        }

        int prefix = 7;
        byte[] big = new byte[prefix + 32];
        RANDOM.nextBytes(big);
        byte[] savedPrefix = Arrays.copyOf(big, prefix);

        long refB = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(refB, key);
            macNI.engineUpdate(refB, input, 0, input.length);
            Assertions.assertEquals(32, macNI.doFinal(refB, big, prefix));
        }
        finally
        {
            macNI.dispose(refB);
        }

        // (1) bytes before the offset untouched.
        Assertions.assertArrayEquals(savedPrefix, Arrays.copyOf(big, prefix),
                "prefix region was clobbered");
        // (2) output region is exactly the reference MAC.
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(big, prefix, prefix + 32),
                "output region is not the expected MAC");
        // (3) a window one byte earlier is NOT the MAC — proves the write
        //     landed at exactly `prefix`.
        Assertions.assertFalse(
                Arrays.equals(reference, Arrays.copyOfRange(big, prefix - 1, prefix - 1 + 32)),
                "MAC appears one byte before the requested offset");
    }

    // ---------------------------------------------------------------------
    // Aliased-buffer operation (testing.md). MAC has no single in->out
    // transform (update only reads, doFinal only writes), so the meaningful
    // aliased case is a caller reusing the update-input array as the
    // doFinal-output array — appending the tag into the message buffer, or
    // overwriting the already-consumed message with its MAC. Verified
    // empirically to be supported on both backends; the tag must be correct
    // and the ENTIRE destination outside the tag region must be untouched.
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_aliased_tagAfterMessage() throws Exception
    {
        // Tag written immediately past the message, no overlap.
        assertAliasedMacCorrect(40, 40);
    }

    @Test
    public void doFinal_aliased_tagOverwritesMessageStart() throws Exception
    {
        // Tag lands on the already-consumed message bytes (offset 0).
        assertAliasedMacCorrect(40, 0);
    }

    @Test
    public void doFinal_aliased_tagMidMessage() throws Exception
    {
        // Tag lands inside the consumed region.
        assertAliasedMacCorrect(64, 16);
    }

    /**
     * update from {@code buf[0..msgLen)} then write the MAC into the SAME
     * array at {@code tagOff}, and assert: (1) the tag region equals the
     * reference MAC of the message, and (2) every byte of the destination
     * OUTSIDE the tag region is byte-identical to a pre-call snapshot —
     * nothing accidentally clobbered.
     */
    private void assertAliasedMacCorrect(int msgLen, int tagOff) throws Exception
    {
        byte[] key = new byte[32];
        byte[] msg = new byte[msgLen];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(msg);

        // Reference HMAC-SHA256 of the message via separate buffers.
        byte[] reference = new byte[32];
        long refA = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(refA, key);
            macNI.engineUpdate(refA, msg, 0, msg.length);
            Assertions.assertEquals(32, macNI.doFinal(refA, reference, 0));
        }
        finally
        {
            macNI.dispose(refA);
        }

        int cap = Math.max(msgLen, tagOff + 32) + 8;
        byte[] buf = new byte[cap];
        RANDOM.nextBytes(buf);
        System.arraycopy(msg, 0, buf, 0, msgLen);
        byte[] snapshot = buf.clone();   // includes the planted message

        int written;
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(ref, key);
            macNI.engineUpdate(ref, buf, 0, msgLen);
            written = macNI.doFinal(ref, buf, tagOff);
        }
        finally
        {
            macNI.dispose(ref);
        }

        String where = "msgLen=" + msgLen + " tagOff=" + tagOff;
        Assertions.assertEquals(32, written, where + " tag length");

        // (1) tag region equals the reference MAC.
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(buf, tagOff, tagOff + written),
                where + ": aliased MAC differs from the reference");
        // (2) WHOLE destination: everything outside the tag region is
        //     byte-identical to the snapshot — nothing whacked.
        Assertions.assertArrayEquals(Arrays.copyOf(snapshot, tagOff), Arrays.copyOf(buf, tagOff),
                where + ": bytes before the tag offset were clobbered");
        Assertions.assertArrayEquals(
                Arrays.copyOfRange(snapshot, tagOff + written, cap),
                Arrays.copyOfRange(buf, tagOff + written, cap),
                where + ": bytes after the tag were clobbered");
    }

    // ---------------------------------------------------------------------
    // Length queries and reset state guards.
    // ---------------------------------------------------------------------

    @Test
    public void getMacLength_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> macNI.getMacLength(ref));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_hmac_beforeInit_returnsDigestSize()
    {
        // macLengthMeta is keyless — it reads the digest output size from
        // algorithm metadata and MUST answer before init.
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            Assertions.assertEquals(32, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_cmac_beforeInit_returnsBlockSize()
    {
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            // CMAC length == AES block size (16), independent of key.
            Assertions.assertEquals(16, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_hmac_unknownDigest_opensslError()
    {
        long ref = macNI.allocateMac("HMAC", "NOT-A-REAL-DIGEST");
        Assertions.assertTrue(ref > 0);
        try
        {
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> macNI.macLengthMeta(ref));
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:")
                    && e.getMessage().contains("NOT-A-REAL-DIGEST"), e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void reset_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> macNI.reset(ref));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void reset_nullRef_isNoOp()
    {
        // Both backends return JO_SUCCESS for the spurious-reset case.
        macNI.reset(0L);
    }

    // ---------------------------------------------------------------------
    // Null (0) mac_ctx handle: every dereferencing entry point must return a
    // typed JO_MAC_CTX_IS_NULL rejection (IllegalArgumentException "mac
    // context is null"), NOT a jo_assert that aborts the JVM. dispose/reset
    // deliberately no-op on a null handle (see reset_nullRef_isNoOp).
    // ---------------------------------------------------------------------

    @Test
    public void init_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineInit(0L, new byte[16]));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void updateByte_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineUpdate(0L, (byte) 1));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void updateBytes_nullCtx_rejectedTyped()
    {
        // ctx is checked before the input/range checks, so a non-null input
        // with a null handle still surfaces the handle rejection.
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineUpdate(0L, new byte[4], 0, 4));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void doFinal_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.doFinal(0L, new byte[32], 0));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void getMacLength_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.getMacLength(0L));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void macLengthMeta_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.macLengthMeta(0L));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    // ---------------------------------------------------------------------

    private interface RefBody
    {
        void run(long ref) throws Exception;
    }

    private void withInitedHmac(RefBody body)
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
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
            macNI.dispose(ref);
        }
    }
}
