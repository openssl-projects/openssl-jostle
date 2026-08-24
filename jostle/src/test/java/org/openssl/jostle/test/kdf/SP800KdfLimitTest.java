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

package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;
import java.security.Security;

/**
 * NI-layer input-validation tests for the three SP 800-x KDF bridges
 * ({@code KdfNI.kbkdf}, {@code sskdf}, {@code sshkdf}), mirroring
 * {@link HkdfLimitTest}. Both the JNI and the FFI bridge must return identical
 * codes for identical inputs, so every case here runs against whichever bridge
 * {@code TestNISelector} resolves and the matrix runs both.
 *
 * <p>Beyond the usual null / negative / range set, two cases here are
 * load-bearing rather than routine:</p>
 * <ol>
 *   <li>{@code outLen == 0}. SSHKDF ACCEPTS a zero-length request in OpenSSL
 *       and emits a zero-length key — a derived key equal to every other
 *       zero-length key. The refusal is the bridge's, so it is pinned for all
 *       three KDFs.</li>
 *   <li>The optional-vs-mandatory split. KBKDF's Label and Context and SSKDF's
 *       FixedInfo accept null; SSHKDF's exchange hash and session id do NOT,
 *       because RFC 4253 defines no absent form for them. A bridge that
 *       accepted null there would derive from an empty H, which is the kind of
 *       silently-wrong-but-consistent result no round trip can see.</li>
 * </ol>
 */
public class SP800KdfLimitTest
{
    private final KdfNI kdfNI = TestNISelector.getKDFNI();

    private static final String COUNTER = "COUNTER";
    private static final String HMAC = "HMAC";

    private static final byte[] KI = new byte[32];
    private static final byte[] H20 = new byte[20];

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private int kbkdf(byte[] out, int off, int len)
    {
        return kdfNI.kbkdf(COUNTER, HMAC, "SHA-256", null, KI, null, null, null, 32, 0, 0,
                out, off, len);
    }

    private int sskdf(byte[] out, int off, int len)
    {
        return kdfNI.sskdf("SHA-256", KI, null, out, off, len);
    }

    private int sshkdf(byte[] out, int off, int len)
    {
        return kdfNI.sshkdf("SHA-256", KI, H20, H20, "A", out, off, len);
    }

    // -------------------------------------------------- mandatory inputs

    @Test
    public void kbkdf_nullMode()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(null, HMAC, "SHA-256", null, KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown mode", e.getMessage());
    }

    @Test
    public void kbkdf_emptyMode()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf("", HMAC, "SHA-256", null, KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown mode", e.getMessage());
    }

    @Test
    public void kbkdf_unknownModeReachesOpenSSL()
    {
        // Whether a non-empty mode name is one OpenSSL knows is OpenSSL's
        // question (classify-don't-pre-check), so this must surface as a real
        // provider error, not a Java-side rejection.
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf("SIDEWAYS", HMAC, "SHA-256", null, KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + e.getMessage());
    }

    @Test
    public void kbkdf_nullMac()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, null, "SHA-256", null, KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown mac", e.getMessage());
    }

    @Test
    public void kbkdf_emptyMac()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, "", "SHA-256", null, KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown mac", e.getMessage());
    }

    @Test
    public void kbkdf_neitherDigestNorCipher()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, HMAC, null, null, KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown digest", e.getMessage());
    }

    @Test
    public void kbkdf_bothDigestAndCipherEmpty()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, HMAC, "", "", KI,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown digest", e.getMessage());
    }

    @Test
    public void kbkdf_nullKey()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.kbkdf(COUNTER, HMAC, "SHA-256", null, null,
                        null, null, null, 32, 0, 0, new byte[16], 0, 16)));
        Assertions.assertEquals("secret is null", e.getMessage());
    }

    @Test
    public void sskdf_nullDigest()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.sskdf(null, KI, null, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown digest", e.getMessage());
    }

    @Test
    public void sskdf_emptyDigest()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.sskdf("", KI, null, new byte[16], 0, 16)));
        Assertions.assertEquals("unknown digest", e.getMessage());
    }

    @Test
    public void sskdf_nullSecret()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kdfNI.sskdf("SHA-256", null, null, new byte[16], 0, 16)));
        Assertions.assertEquals("secret is null", e.getMessage());
    }

    @Test
    public void sshkdf_nullDigest()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf(null, KI, H20, H20, "A", new byte[16], 0, 16)));
        Assertions.assertEquals("unknown digest", e.getMessage());
    }

    @Test
    public void sshkdf_nullKey()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf("SHA-256", null, H20, H20, "A", new byte[16], 0, 16)));
        Assertions.assertEquals("secret is null", e.getMessage());
    }

    @Test
    public void sshkdf_nullExchangeHash()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf("SHA-256", KI, null, H20, "A", new byte[16], 0, 16)));
        Assertions.assertEquals("exchange hash is null", e.getMessage());
    }

    @Test
    public void sshkdf_nullSessionId()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf("SHA-256", KI, H20, null, "A", new byte[16], 0, 16)));
        Assertions.assertEquals("session id is null", e.getMessage());
    }

    @Test
    public void sshkdf_nullType()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf("SHA-256", KI, H20, H20, null, new byte[16], 0, 16)));
        Assertions.assertEquals("ssh key type is null or empty", e.getMessage());
    }

    @Test
    public void sshkdf_emptyType()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf("SHA-256", KI, H20, H20, "", new byte[16], 0, 16)));
        Assertions.assertEquals("ssh key type is null or empty", e.getMessage());
    }

    @Test
    public void sshkdf_unknownTypeReachesOpenSSL()
    {
        // "G" is outside RFC 4253's A..F. Left to OpenSSL deliberately, which
        // refuses it with "value error" on every supported build.
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                () -> kdfNI.handleErrorCodes(
                        kdfNI.sshkdf("SHA-256", KI, H20, H20, "G", new byte[16], 0, 16)));
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + e.getMessage());
    }

    // --------------------------------------------------- optional inputs

    /**
     * The optional inputs really are optional at the NI surface — this is the
     * only way to reach the C {@code label == NULL} / {@code context == NULL} /
     * {@code info == NULL} paths, since the specs normalise before the SPI.
     */
    @Test
    public void optionalInputsAcceptNull()
    {
        byte[] out = new byte[32];
        Assertions.assertEquals(0, kbkdf(out, 0, out.length),
                "KBKDF must accept a null Label, Context and IV");
        Assertions.assertFalse(Arrays.areEqual(out, new byte[32]), "KBKDF derived all-zero");

        byte[] out2 = new byte[32];
        Assertions.assertEquals(0, sskdf(out2, 0, out2.length),
                "SSKDF must accept a null FixedInfo");
        Assertions.assertFalse(Arrays.areEqual(out2, new byte[32]), "SSKDF derived all-zero");
    }

    // ------------------------------------------------------ output buffer

    @Test
    public void nullOutput()
    {
        Assertions.assertEquals("output is null", Assertions.assertThrows(
                NullPointerException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(null, 0, 16))).getMessage());
        Assertions.assertEquals("output is null", Assertions.assertThrows(
                NullPointerException.class,
                () -> kdfNI.handleErrorCodes(sskdf(null, 0, 16))).getMessage());
        Assertions.assertEquals("output is null", Assertions.assertThrows(
                NullPointerException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(null, 0, 16))).getMessage());
    }

    @Test
    public void negativeOutputOffset()
    {
        for (int off : new int[]{-1, Integer.MIN_VALUE})
        {
            Assertions.assertEquals("output offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kbkdf(new byte[16], off, 16))).getMessage());
            Assertions.assertEquals("output offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(sskdf(new byte[16], off, 16))).getMessage());
            Assertions.assertEquals("output offset is negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(sshkdf(new byte[16], off, 16))).getMessage());
        }
    }

    @Test
    public void negativeOutputLength()
    {
        for (int len : new int[]{-1, Integer.MIN_VALUE})
        {
            Assertions.assertEquals("output len negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(kbkdf(new byte[16], 0, len))).getMessage());
            Assertions.assertEquals("output len negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(sskdf(new byte[16], 0, len))).getMessage());
            Assertions.assertEquals("output len negative", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> kdfNI.handleErrorCodes(sshkdf(new byte[16], 0, len))).getMessage());
        }
    }

    /**
     * The load-bearing one. OpenSSL's SSHKDF accepts {@code outLen == 0} and
     * writes a zero-length key; KBKDF and SSKDF refuse it themselves. The
     * bridge refuses it uniformly so a caller need not know which is which,
     * and so the typed message is the same across the three.
     */
    @Test
    public void zeroOutputLengthRefused()
    {
        Assertions.assertEquals("output len is zero", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(new byte[16], 0, 0))).getMessage());
        Assertions.assertEquals("output len is zero", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sskdf(new byte[16], 0, 0))).getMessage());
        Assertions.assertEquals("output len is zero", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(new byte[16], 0, 0))).getMessage());
    }

    @Test
    public void outputRangePastEnd_lenEdge()
    {
        // Boundary + 1 on the length side: 0 + 11 > 10.
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(new byte[10], 0, 11))).getMessage());
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sskdf(new byte[10], 0, 11))).getMessage());
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(new byte[10], 0, 11))).getMessage());
    }

    @Test
    public void outputRangePastEnd_offsetEdge()
    {
        // Boundary + 1 on the offset side: 1 + 10 > 10.
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(kbkdf(new byte[10], 1, 10))).getMessage());
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sskdf(new byte[10], 1, 10))).getMessage());
        Assertions.assertEquals("output offset + length is out of range", Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> kdfNI.handleErrorCodes(sshkdf(new byte[10], 1, 10))).getMessage());
    }

    /**
     * Positive companion to the two past-end probes: offset + len == size is
     * exactly in range, so the boundary sits exactly past the end and not one
     * byte earlier.
     */
    @Test
    public void outputRangeAtEndAccepted()
    {
        Assertions.assertEquals(0, kbkdf(new byte[42], 10, 32));
        Assertions.assertEquals(0, sskdf(new byte[42], 10, 32));
        Assertions.assertEquals(0, sshkdf(new byte[42], 10, 32));
    }

    // ------------------------------------------------------- offset write

    /**
     * Offset-write contract (4-step), one per KDF: random-fill, prefix
     * snapshot, prefix untouched, window at offset equals the zero-offset
     * derivation, shifted-by-one window does NOT.
     */
    @Test
    public void writesAtOffsetWithoutClobberingPrefix()
    {
        SecureRandom sr = new SecureRandom();
        byte[] ki = new byte[32];
        byte[] h = new byte[24];
        sr.nextBytes(ki);
        sr.nextBytes(h);
        int len = 40;
        int prefix = 7;

        checkOffsetWrite(sr, prefix, len,
                (out, off) -> kdfNI.kbkdf(COUNTER, HMAC, "SHA-256", null, ki, h, h, null,
                        32, 1, 1, out, off, len), "kbkdf");
        checkOffsetWrite(sr, prefix, len,
                (out, off) -> kdfNI.sskdf("SHA-256", ki, h, out, off, len), "sskdf");
        checkOffsetWrite(sr, prefix, len,
                (out, off) -> kdfNI.sshkdf("SHA-256", ki, h, h, "C", out, off, len), "sshkdf");
    }

    private interface Derive
    {
        int run(byte[] out, int off);
    }

    private static void checkOffsetWrite(SecureRandom sr, int prefix, int len,
                                         Derive derive, String what)
    {
        byte[] reference = new byte[len];
        Assertions.assertEquals(0, derive.run(reference, 0), what + " reference derive");

        byte[] big = new byte[prefix + len + 4];
        sr.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);
        byte[] expectedTail = new byte[4];
        System.arraycopy(big, prefix + len, expectedTail, 0, 4);

        Assertions.assertEquals(0, derive.run(big, prefix), what + " offset derive");

        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                what + " modified bytes preceding outOffset");

        byte[] actualTail = new byte[4];
        System.arraycopy(big, prefix + len, actualTail, 0, 4);
        Assertions.assertArrayEquals(expectedTail, actualTail,
                what + " modified bytes past outOffset + len");

        byte[] window = new byte[len];
        System.arraycopy(big, prefix, window, 0, len);
        Assertions.assertArrayEquals(reference, window,
                what + " output at offset differs from the zero-offset derivation");

        byte[] shifted = new byte[len];
        System.arraycopy(big, prefix - 1, shifted, 0, len);
        Assertions.assertFalse(Arrays.areEqual(reference, shifted),
                what + " appears to have written at outOffset - 1");
    }
}
