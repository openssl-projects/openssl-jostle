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

import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES key wrap on the INVERSE cipher function (SP 800-38F 5.1), which OpenSSL
 * calls {@code AES-<n>-WRAP-INV} and Jostle registers as
 * {@code Cipher.AESWrapInv}.
 *
 * <p>Two things differ from {@link AESKeyWrapTest}. There is no JCE name to
 * agree on — BC registers no transformation for this direction — so the
 * interop anchor is its lightweight {@code AESWrapEngine(true)}, still an
 * independent implementation. And a wrong mode mapping round-trips perfectly:
 * had WRAP_INV fallen through to plain WRAP, every positive test here would
 * pass on self-consistent output of the wrong construction. So the
 * load-bearing assertions are the cross-checks against plain AESWrap.
 */
public class AESKeyWrapInvTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /** The registered primary, its alias, and the three mode spellings. */
    private static final String[] NAMES = {
            "AESWrapInv", "AESWRAPINV", "aeswrapinv", "AESKWINV",
            "AES/WRAP_INV/NoPadding", "AES/KWINV/NoPadding", "AES/WRAP-INV/NoPadding"
    };

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] jslWrap(String name, byte[] kek, byte[] cek) throws Exception
    {
        Cipher c = Cipher.getInstance(name, JSL);
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
        return c.wrap(new SecretKeySpec(cek, "AES"));
    }

    private static byte[] jslUnwrap(String name, byte[] kek, byte[] wrapped) throws Exception
    {
        Cipher c = Cipher.getInstance(name, JSL);
        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
        return c.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded();
    }

    private static byte[] bcEngineWrap(byte[] kek, byte[] cek)
    {
        AESWrapEngine e = new AESWrapEngine(true);
        e.init(true, new KeyParameter(kek));
        return e.wrap(cek, 0, cek.length);
    }

    private static byte[] bcEngineUnwrap(byte[] kek, byte[] wrapped) throws Exception
    {
        AESWrapEngine e = new AESWrapEngine(true);
        e.init(false, new KeyParameter(kek));
        return e.unwrap(wrapped, 0, wrapped.length);
    }

    /**
     * The one published inverse-direction vector: BC's {@code AESWrapTest}
     * case 7, reproduced from OpenSSL on mainline and both FIPS modules by
     * {@code wrapinv_probe.c}. Paired with two differentiators, since a KAT
     * alone is satisfied by an implementation that ignores part of its input.
     */
    @Test
    public void inverseWrapKatVector() throws Exception
    {
        byte[] kek = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] cek = Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[] expected =
                Hex.decode("cba01acbdb4c7c39fa59babb383c485f318837208731a81c735b5be6ba710375a1159e26a9b57228");

        Assertions.assertArrayEquals(expected, jslWrap("AESWrapInv", kek, cek), "inverse KW vector");
        Assertions.assertArrayEquals(cek, jslUnwrap("AESWrapInv", kek, expected), "inverse KW unwrap");

        byte[] cekFlipped = Arrays.clone(cek);
        cekFlipped[7] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(expected, jslWrap("AESWrapInv", kek, cekFlipped)),
                "a one-bit payload change must change the wrapped output");

        byte[] kekFlipped = Arrays.clone(kek);
        kekFlipped[31] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(expected, jslWrap("AESWrapInv", kekFlipped, cek)),
                "a one-bit KEK change must change the wrapped output");
    }

    /**
     * THE test for this work item. A mapping that silently resolved WRAP_INV
     * to plain WRAP would pass every other test here, so both halves are
     * asserted: the constructions differ, and neither reads the other's
     * output. All three widths, since each has its own fetch arm.
     */
    @Test
    public void inverseIsNotPlainWrap() throws Exception
    {
        SecureRandom sr = seededRandom("inverseIsNotPlainWrap");

        for (int kekLen : new int[]{16, 24, 32})
        {
            byte[] kek = new byte[kekLen];
            sr.nextBytes(kek);
            byte[] cek = new byte[32];
            sr.nextBytes(cek);
            String where = "kek" + kekLen;

            byte[] inv = jslWrap("AESWrapInv", kek, cek);
            byte[] fwd = jslWrap("AESWrap", kek, cek);

            Assertions.assertFalse(Arrays.areEqual(inv, fwd),
                    where + ": WRAP_INV produced the same bytes as plain WRAP — the mode did not invert");

            // Both directions of the cross-check: each unwrapper must reject
            // the other's output at the integrity check.
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> jslUnwrap("AESWrap", kek, inv),
                    where + ": plain AESWrap accepted inverse-wrapped output");
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> jslUnwrap("AESWrapInv", kek, fwd),
                    where + ": AESWrapInv accepted forward-wrapped output");
        }
    }

    /**
     * Agreement with BC's lightweight engine (BC registers no JCE name for
     * this direction), both directions, all three KEK widths, every legal
     * payload length to 64 bytes, over ten trials of random keys and payloads.
     */
    @Test
    public void agreesWithBouncyCastleEngineBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBouncyCastleEngineBothDirections");

        for (int trial = 0; trial < 10; trial++)
        {
            for (int kekLen : new int[]{16, 24, 32})
            {
                byte[] kek = new byte[kekLen];
                sr.nextBytes(kek);

                for (int cekLen = 16; cekLen <= 64; cekLen += 8)
                {
                    byte[] cek = new byte[cekLen];
                    sr.nextBytes(cek);
                    String where = "trial" + trial + "/kek" + kekLen + "/cek" + cekLen;

                    byte[] jsl = jslWrap("AESWrapInv", kek, cek);
                    byte[] bc = bcEngineWrap(kek, cek);
                    Assertions.assertTrue(Arrays.areEqual(bc, jsl),
                            where + ": JSL and the BC engine wrapped differently");

                    // JSL-wrap -> BC-unwrap.
                    Assertions.assertTrue(Arrays.areEqual(cek, bcEngineUnwrap(kek, jsl)),
                            where + ": BC could not unwrap JSL output");

                    // BC-wrap -> JSL-unwrap.
                    Assertions.assertTrue(Arrays.areEqual(cek, jslUnwrap("AESWrapInv", kek, bc)),
                            where + ": JSL could not unwrap BC output");
                }
            }
        }
    }

    /**
     * Every name and mode spelling reaches the same construction. The three
     * transformation forms go through form-4 lookup into
     * {@code engineSetMode}, where a mis-spelled alias would silently land on
     * a different mode.
     */
    @Test
    public void everyNameAndModeSpellingResolvesToTheSameConstruction() throws Exception
    {
        SecureRandom sr = seededRandom("everyNameAndModeSpellingResolvesToTheSameConstruction");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);
        byte[] cek = new byte[24];
        sr.nextBytes(cek);

        byte[] reference = bcEngineWrap(kek, cek);

        for (String name : NAMES)
        {
            Assertions.assertTrue(Arrays.areEqual(reference, jslWrap(name, kek, cek)),
                    name + ": did not produce the inverse-wrap construction");
            Assertions.assertTrue(Arrays.areEqual(cek, jslUnwrap(name, kek, reference)),
                    name + ": did not unwrap the inverse-wrap construction");
        }
    }

    /**
     * A tampered blob must fail the integrity check as
     * {@link InvalidKeyException} — the JCE-contracted type. Every byte
     * position in turn, so a check covering only the 8-byte integrity block
     * cannot pass.
     *
     * <p>The native layer now raises {@code BadPaddingException} for a failed
     * unwrap integrity check, matching BouncyCastle (2026-08-31); it used to
     * raise {@code OpenSSLException}. Either way {@code engineUnwrap} converts
     * to {@code InvalidKeyException}, which is what this pins.
     *
     * <p>NOTE, and it is a real loss rather than a tidy-up: this test also used
     * to assert that the recovery path had not scrubbed the OpenSSL error queue,
     * by requiring the message to carry queue content and not end in "null".
     * That guard has no observable left — the message is now the typed one and
     * does not come from the queue at all. The mark/pop discipline in
     * {@code wrap_recover_after_failure} is consequently unguarded from here.
     */
    @Test
    public void tamperedWrappedKeyRejectedTyped() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedWrappedKeyRejectedTyped");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);
        byte[] cek = new byte[32];
        sr.nextBytes(cek);

        byte[] wrapped = jslWrap("AESWrapInv", kek, cek);

        for (int i = 0; i < wrapped.length; i++)
        {
            byte[] bad = Arrays.clone(wrapped);
            bad[i] ^= (byte) 0x01;
            final int pos = i;
            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> jslUnwrap("AESWrapInv", kek, bad),
                    "tampering at byte " + pos + " was not rejected");
            Assertions.assertEquals("unable to unwrap key: invalid cipher text", ex.getMessage(),
                    "byte " + pos + ": unexpected message");
        }

        // A wrong KEK is the other integrity failure, and must present the
        // same way.
        byte[] wrongKek = Arrays.clone(kek);
        wrongKek[0] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> jslUnwrap("AESWrapInv", wrongKek, wrapped),
                "a wrong KEK must fail the integrity check");
    }

    /**
     * KEK length boundaries: 16 / 24 / 32 only, each probed with the value on
     * either side. {@code SecretKeySpec} accepts any non-empty array, so the
     * rejection must come from the provider — which is the point.
     */
    @Test
    public void kekLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("kekLengthBoundaries");
        byte[] cek = new byte[16];
        sr.nextBytes(cek);

        for (int len : new int[]{15, 16, 17, 23, 24, 25, 31, 32, 33, 64})
        {
            byte[] kek = new byte[len];
            sr.nextBytes(kek);
            boolean valid = (len == 16 || len == 24 || len == 32);

            if (valid)
            {
                Assertions.assertNotNull(jslWrap("AESWrapInv", kek, cek),
                        "KEK length " + len + " must be accepted");
            }
            else
            {
                Assertions.assertThrows(Exception.class,
                        () -> jslWrap("AESWrapInv", kek, cek),
                        "KEK length " + len + " must be rejected");
            }
        }
    }

    /**
     * Payload length boundaries. RFC 3394 wants a multiple of 8 and at least
     * two semiblocks; unwrap needs a third for the integrity block. Both
     * floors measured in {@code wrapinv_probe.c} Q4. Accepted lengths must
     * round-trip, not merely return — the right length of garbage would pass a
     * did-not-throw assertion.
     */
    @Test
    public void payloadLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("payloadLengthBoundaries");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);

        // Below the two-semiblock floor, and every non-multiple of 8 around it.
        for (int len : new int[]{1, 7, 8, 9, 15, 17, 20, 23, 25})
        {
            byte[] cek = new byte[len];
            sr.nextBytes(cek);
            Assertions.assertThrows(Exception.class,
                    () -> jslWrap("AESWrapInv", kek, cek),
                    "payload length " + len + " must be rejected");
        }

        for (int len : new int[]{16, 24, 32, 40, 128})
        {
            byte[] cek = new byte[len];
            sr.nextBytes(cek);
            byte[] wrapped = jslWrap("AESWrapInv", kek, cek);
            Assertions.assertEquals(len + 8, wrapped.length,
                    "payload length " + len + ": wrapped length");
            Assertions.assertTrue(Arrays.areEqual(cek, jslUnwrap("AESWrapInv", kek, wrapped)),
                    "payload length " + len + ": round trip");
        }

        // Unwrap floor: a blob shorter than three semiblocks carries no payload.
        byte[] shortBlob = new byte[16];
        sr.nextBytes(shortBlob);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> jslUnwrap("AESWrapInv", kek, shortBlob),
                "a 16-byte blob is below the unwrap floor");
    }

    /**
     * Reset and reuse. Key wrap is deterministic, so one instance driven twice
     * gives identical output for identical input and different for different;
     * and a failure must not poison the instance for what follows.
     */
    @Test
    public void reusableAcrossOperationsAndAfterFailure() throws Exception
    {
        SecureRandom sr = seededRandom("reusableAcrossOperationsAndAfterFailure");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);
        byte[] cekA = new byte[16];
        sr.nextBytes(cekA);
        byte[] cekB = new byte[24];
        sr.nextBytes(cekB);

        Cipher c = Cipher.getInstance("AESWrapInv", JSL);
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
        byte[] first = c.wrap(new SecretKeySpec(cekA, "AES"));
        byte[] again = c.wrap(new SecretKeySpec(cekA, "AES"));
        byte[] other = c.wrap(new SecretKeySpec(cekB, "AES"));

        Assertions.assertTrue(Arrays.areEqual(first, again),
                "key wrap is deterministic; the reused instance diverged");
        Assertions.assertFalse(Arrays.areEqual(first, other),
                "different payloads must wrap differently on a reused instance");
        Assertions.assertTrue(Arrays.areEqual(bcEngineWrap(kek, cekB), other),
                "the third operation on the reused instance no longer matches BC");

        Cipher u = Cipher.getInstance("AESWrapInv", JSL);
        u.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));

        byte[] bad = Arrays.clone(first);
        bad[0] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> u.unwrap(bad, "AES", Cipher.SECRET_KEY));

        Key recovered = u.unwrap(first, "AES", Cipher.SECRET_KEY);
        Assertions.assertTrue(Arrays.areEqual(cekA, recovered.getEncoded()),
                "the failed unwrap poisoned the instance");
    }

    /**
     * The mode takes no IV, so an {@code IvParameterSpec} must be refused, not
     * ignored — silently ignoring it leaves a caller believing the wrap is
     * IV-bound when it is not.
     */
    @Test
    public void ivIsRejected() throws Exception
    {
        SecureRandom sr = seededRandom("ivIsRejected");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);
        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        Cipher c = Cipher.getInstance("AESWrapInv", JSL);
        Assertions.assertThrows(Exception.class,
                () -> c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"),
                        new javax.crypto.spec.IvParameterSpec(iv)),
                "AESWrapInv must not accept an IV");
    }
}
