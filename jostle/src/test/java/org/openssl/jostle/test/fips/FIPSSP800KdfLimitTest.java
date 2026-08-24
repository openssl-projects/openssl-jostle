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
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS NI surface for the three SP 800-x
 * KDFs ({@code FIPSNISelector.KdfNI.kbkdf / sskdf / sshkdf}). The FIPS JNI glue
 * is the base {@code kdf_jni.c} re-included under renamed symbols, so the
 * bridge's null / negative / range rejections are identical by construction —
 * this pins that they survived into the FIPS interface library with the same
 * messages. Mirrors the base {@code kdf/SP800KdfLimitTest}.
 *
 * <p>The interesting half is {@link #keyFloorContract()}: {@code kbkdf-key-check},
 * {@code sskdf-key-check} and {@code sshkdf-key-check} are {@code fipsinstall}
 * switches, present on a {@code -pedantic} configuration and absent from
 * FIPS 3.1.2 entirely. JSLFIPS ships ONE build that must serve both, so the
 * test probes and asserts BOTH branches rather than pinning either module's
 * answer (see testing.md, "Where two supported environments disagree, assert
 * the CONTRACT").</p>
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).</p>
 */
public class FIPSSP800KdfLimitTest
{
    private static final String COUNTER = "COUNTER";
    private static final String HMAC = "HMAC";

    /** A key that clears the module's 112-bit floor whether or not it is on. */
    private static final byte[] CONFORMING_KEY = new byte[32];
    private static final byte[] H20 = new byte[20];

    private final KdfNI kdfNI = FIPSNISelector.KdfNI;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        new SecureRandom().nextBytes(CONFORMING_KEY);
    }

    private int kbkdf(byte[] key, byte[] out, int off, int len)
    {
        return kdfNI.kbkdf(COUNTER, HMAC, "SHA-256", null, key, null, null, null, 32, 0, 0,
                out, off, len);
    }

    private int sskdf(byte[] secret, byte[] out, int off, int len)
    {
        return kdfNI.sskdf("SHA-256", secret, null, out, off, len);
    }

    private int sshkdf(byte[] key, byte[] out, int off, int len)
    {
        return kdfNI.sshkdf("SHA-256", key, H20, H20, "A", out, off, len);
    }

    // ------------------------------------------------- bridge rejections

    @Test
    public void kbkdf_nullMode()
    {
        Assertions.assertEquals("unknown mode", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(null, HMAC, "SHA-256", null,
                        CONFORMING_KEY, null, null, null, 32, 0, 0, new byte[16], 0, 16)))
                .getMessage());
    }

    @Test
    public void kbkdf_nullMac()
    {
        Assertions.assertEquals("unknown mac", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, null, "SHA-256", null,
                        CONFORMING_KEY, null, null, null, 32, 0, 0, new byte[16], 0, 16)))
                .getMessage());
    }

    @Test
    public void kbkdf_neitherDigestNorCipher()
    {
        Assertions.assertEquals("unknown digest", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, HMAC, null, null,
                        CONFORMING_KEY, null, null, null, 32, 0, 0, new byte[16], 0, 16)))
                .getMessage());
    }

    @Test
    public void nullKeyingInput()
    {
        Assertions.assertEquals("secret is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(null, new byte[16], 0, 16))).getMessage());
        Assertions.assertEquals("secret is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sskdf(null, new byte[16], 0, 16))).getMessage());
        Assertions.assertEquals("secret is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(null, new byte[16], 0, 16))).getMessage());
    }

    @Test
    public void sshkdf_mandatoryInputsRejectNull()
    {
        Assertions.assertEquals("exchange hash is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.sshkdf("SHA-256", CONFORMING_KEY, null, H20,
                        "A", new byte[16], 0, 16))).getMessage());
        Assertions.assertEquals("session id is null", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.sshkdf("SHA-256", CONFORMING_KEY, H20, null,
                        "A", new byte[16], 0, 16))).getMessage());
        Assertions.assertEquals("ssh key type is null or empty", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.sshkdf("SHA-256", CONFORMING_KEY, H20, H20,
                        null, new byte[16], 0, 16))).getMessage());
    }

    @Test
    public void nullOutput()
    {
        Assertions.assertEquals("output is null", Assertions.assertThrows(
                NullPointerException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(CONFORMING_KEY, null, 0, 16))).getMessage());
        Assertions.assertEquals("output is null", Assertions.assertThrows(
                NullPointerException.class,
                () -> kdfNI.handleErrorCodes(sskdf(CONFORMING_KEY, null, 0, 16))).getMessage());
        Assertions.assertEquals("output is null", Assertions.assertThrows(
                NullPointerException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(CONFORMING_KEY, null, 0, 16))).getMessage());
    }

    @Test
    public void negativeOutputOffsetAndLength()
    {
        for (int bad : new int[]{-1, Integer.MIN_VALUE})
        {
            Assertions.assertEquals("output offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kbkdf(CONFORMING_KEY, new byte[16], bad, 16)))
                    .getMessage());
            Assertions.assertEquals("output len negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(sskdf(CONFORMING_KEY, new byte[16], 0, bad)))
                    .getMessage());
            Assertions.assertEquals("output len negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(sshkdf(CONFORMING_KEY, new byte[16], 0, bad)))
                    .getMessage());
        }
    }

    /**
     * SSHKDF accepts a zero-length request in OpenSSL and emits a zero-length
     * key, so the refusal is the bridge's — pinned here against the FIPS
     * library specifically, since that is the one whose zero-length key would
     * be handed to a caller believing it came from a validated module.
     */
    @Test
    public void zeroOutputLengthRefused()
    {
        Assertions.assertEquals("output len is zero", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(CONFORMING_KEY, new byte[16], 0, 0)))
                .getMessage());
        Assertions.assertEquals("output len is zero", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sskdf(CONFORMING_KEY, new byte[16], 0, 0)))
                .getMessage());
        Assertions.assertEquals("output len is zero", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(CONFORMING_KEY, new byte[16], 0, 0)))
                .getMessage());
    }

    @Test
    public void outputRangePastEnd()
    {
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(CONFORMING_KEY, new byte[10], 0, 11)))
                .getMessage());
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sskdf(CONFORMING_KEY, new byte[10], 1, 10)))
                .getMessage());
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(CONFORMING_KEY, new byte[10], 1, 10)))
                .getMessage());
    }

    @Test
    public void outputRangeAtEndAccepted()
    {
        Assertions.assertEquals(0, kbkdf(CONFORMING_KEY, new byte[42], 10, 32));
        Assertions.assertEquals(0, sskdf(CONFORMING_KEY, new byte[42], 10, 32));
        Assertions.assertEquals(0, sshkdf(CONFORMING_KEY, new byte[42], 10, 32));
    }

    // ------------------------------------------------- the key-floor gate

    /**
     * The SP 800-131A 112-bit key floor is a {@code fipsinstall} switch, not a
     * module-version property: a 13-byte key derives happily on FIPS 3.1.2 and
     * on a default-configured 3.5.x module, and is refused with "invalid key
     * length" once {@code kbkdf-key-check} / {@code sskdf-key-check} /
     * {@code sshkdf-key-check} are configured.
     *
     * <p>So this asserts the CONTRACT in both directions, per KDF: whichever
     * branch the loaded module takes, a 14-byte key MUST derive, and a 13-byte
     * key must either derive cleanly or be refused with the module's own typed
     * error — never produce a short-keyed derivation while claiming success,
     * and never fail for some other reason.</p>
     */
    @Test
    public void keyFloorContract()
    {
        SecureRandom sr = new SecureRandom();

        // At the floor: must always work, on every supported configuration.
        byte[] atFloor = new byte[FIPSTestUtil.HMAC_MIN_KEY_BYTES];
        sr.nextBytes(atFloor);
        for (String what : new String[]{"kbkdf", "sskdf", "sshkdf"})
        {
            byte[] out = new byte[32];
            Assertions.assertEquals(0, derive(what, atFloor, out),
                    what + ": a " + atFloor.length + "-byte key must always be accepted");
            Assertions.assertFalse(Arrays.areEqual(out, new byte[32]),
                    what + ": derived all-zero at the key floor");
        }

        // One byte below: config-dependent, so both branches are legitimate —
        // but only these two.
        byte[] belowFloor = new byte[FIPSTestUtil.HMAC_MIN_KEY_BYTES - 1];
        sr.nextBytes(belowFloor);
        for (String what : new String[]{"kbkdf", "sskdf", "sshkdf"})
        {
            byte[] out = new byte[32];
            int code = derive(what, belowFloor, out);
            if (code == 0)
            {
                // Floor not configured: the derivation must be real, not a
                // silently-empty one.
                Assertions.assertFalse(Arrays.areEqual(out, new byte[32]),
                        what + ": short key was accepted but derived all-zero");
            }
            else
            {
                // Floor configured: pin the module's own refusal. Asserting the
                // refusal here is what keeps the branch honest — without it
                // this degrades into "anything goes below the floor".
                OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                        () -> kdfNI.handleErrorCodes(code),
                        what + ": a refused short key must surface as OpenSSLException");
                Assertions.assertTrue(e.getMessage().contains("invalid key length"),
                        what + ": unexpected refusal message: " + e.getMessage());
            }
        }
    }

    private int derive(String what, byte[] key, byte[] out)
    {
        if ("kbkdf".equals(what))
        {
            return kbkdf(key, out, 0, out.length);
        }
        if ("sskdf".equals(what))
        {
            return sskdf(key, out, 0, out.length);
        }
        return sshkdf(key, out, 0, out.length);
    }
}
