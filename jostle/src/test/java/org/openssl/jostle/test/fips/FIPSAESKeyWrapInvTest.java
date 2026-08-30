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

import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES key wrap on the inverse cipher function, served by JSLFIPS.
 *
 * <p>The FIPS analogue of {@code crypto/AESKeyWrapInvTest}, not redundant with
 * it: this drives {@code libinterface_fips_*} through the FIPS
 * {@code OSSL_LIB_CTX}, where the base class drives the mainline pair.
 *
 * <p><b>Ungated.</b> All three widths were measured fetchable under
 * {@code fips=yes} on both modules, default and {@code -pedantic} alike
 * ({@code fips-c-review/probes/wrapinv_probe.c}), so absence here is a defect
 * rather than a module property.
 *
 * <p>Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSAESKeyWrapInvTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] wrap(String provider, byte[] kek, byte[] cek) throws Exception
    {
        Cipher c = Cipher.getInstance("AESWrapInv", provider);
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
        return c.wrap(new SecretKeySpec(cek, "AES"));
    }

    private static byte[] unwrap(String provider, byte[] kek, byte[] wrapped) throws Exception
    {
        Cipher c = Cipher.getInstance("AESWrapInv", provider);
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
     * BC's inverse-direction vector ({@code AESWrapTest} case 7), reproduced
     * from OpenSSL on both FIPS modules by {@code wrapinv_probe.c}. Paired
     * with a differentiator, since a KAT alone is satisfied by an
     * implementation that ignores part of its input.
     */
    @Test
    public void inverseWrapKatVector() throws Exception
    {
        byte[] kek = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] cek = Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[] expected =
                Hex.decode("cba01acbdb4c7c39fa59babb383c485f318837208731a81c735b5be6ba710375a1159e26a9b57228");

        Assertions.assertArrayEquals(expected, wrap(FIPS, kek, cek), "inverse KW vector");
        Assertions.assertArrayEquals(cek, unwrap(FIPS, kek, expected), "inverse KW unwrap");

        byte[] flipped = Arrays.clone(cek);
        flipped[0] ^= (byte) 0x01;
        Assertions.assertFalse(Arrays.areEqual(expected, wrap(FIPS, kek, flipped)),
                "a one-bit payload change must change the wrapped output");
    }

    /**
     * Three-way agreement over random keys and payloads: JSLFIPS vs JSL and
     * JSLFIPS vs BC's lightweight engine, both directions for each. The engine
     * rather than a JCE name because BC registers none for this direction.
     */
    @Test
    public void agreesWithJslAndBouncyCastleBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithJslAndBouncyCastleBothDirections");

        for (int trial = 0; trial < 10; trial++)
        {
            for (int kekLen : new int[]{16, 24, 32})
            {
                byte[] kek = new byte[kekLen];
                sr.nextBytes(kek);

                for (int cekLen = 16; cekLen <= 48; cekLen += 8)
                {
                    byte[] cek = new byte[cekLen];
                    sr.nextBytes(cek);
                    String where = "trial" + trial + "/kek" + kekLen + "/cek" + cekLen;

                    byte[] fips = wrap(FIPS, kek, cek);

                    Assertions.assertTrue(Arrays.areEqual(wrap(JSL, kek, cek), fips),
                            where + ": JSLFIPS and JSL wrapped differently");
                    Assertions.assertTrue(Arrays.areEqual(bcEngineWrap(kek, cek), fips),
                            where + ": JSLFIPS and the BC engine wrapped differently");

                    // JSLFIPS wraps, the two references unwrap.
                    Assertions.assertTrue(Arrays.areEqual(cek, unwrap(JSL, kek, fips)),
                            where + ": JSL could not unwrap JSLFIPS output");
                    Assertions.assertTrue(Arrays.areEqual(cek, bcEngineUnwrap(kek, fips)),
                            where + ": BC could not unwrap JSLFIPS output");

                    // The references wrap, JSLFIPS unwraps.
                    Assertions.assertTrue(Arrays.areEqual(cek, unwrap(FIPS, kek, wrap(JSL, kek, cek))),
                            where + ": JSLFIPS could not unwrap JSL output");
                    Assertions.assertTrue(Arrays.areEqual(cek, unwrap(FIPS, kek, bcEngineWrap(kek, cek))),
                            where + ": JSLFIPS could not unwrap BC output");
                }
            }
        }
    }

    /**
     * The discriminator: a mapping that resolved WRAP_INV to plain WRAP would
     * satisfy every other test here, so the constructions must differ and
     * reject each other's output.
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

            byte[] inv = wrap(FIPS, kek, cek);

            Cipher fwdC = Cipher.getInstance("AESWrap", FIPS);
            fwdC.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
            byte[] fwd = fwdC.wrap(new SecretKeySpec(cek, "AES"));

            Assertions.assertFalse(Arrays.areEqual(inv, fwd),
                    where + ": WRAP_INV produced the same bytes as plain WRAP");

            Cipher plain = Cipher.getInstance("AESWrap", FIPS);
            plain.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> plain.unwrap(inv, "AES", Cipher.SECRET_KEY),
                    where + ": plain AESWrap accepted inverse-wrapped output");

            Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(FIPS, kek, fwd),
                    where + ": AESWrapInv accepted forward-wrapped output");
        }
    }

    /**
     * The primary, its alias, and the three mode spellings that go through
     * form-4 lookup all reach the same construction.
     */
    @Test
    public void everyNameAndModeSpellingResolvesToTheSameConstruction() throws Exception
    {
        SecureRandom sr = seededRandom("everyNameAndModeSpellingResolvesToTheSameConstruction");
        byte[] kek = new byte[24];
        sr.nextBytes(kek);
        byte[] cek = new byte[32];
        sr.nextBytes(cek);

        byte[] reference = bcEngineWrap(kek, cek);

        for (String name : new String[]{
                "AESWrapInv", "AESKWINV",
                "AES/WRAP_INV/NoPadding", "AES/KWINV/NoPadding", "AES/WRAP-INV/NoPadding"})
        {
            Cipher c = Cipher.getInstance(name, FIPS);
            c.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
            Assertions.assertTrue(Arrays.areEqual(reference, c.wrap(new SecretKeySpec(cek, "AES"))),
                    name + ": did not produce the inverse-wrap construction");
        }
    }

    /**
     * A tampered blob and a wrong KEK both fail the integrity check as the
     * JCE-contracted {@link InvalidKeyException}, with the pinned message.
     */
    @Test
    public void tamperedWrappedKeyRejectedTyped() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedWrappedKeyRejectedTyped");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);
        byte[] cek = new byte[24];
        sr.nextBytes(cek);

        byte[] wrapped = wrap(FIPS, kek, cek);

        for (int i = 0; i < wrapped.length; i++)
        {
            byte[] bad = Arrays.clone(wrapped);
            bad[i] ^= (byte) 0x01;
            final int pos = i;
            InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(FIPS, kek, bad),
                    "tampering at byte " + pos + " was not rejected");
            Assertions.assertTrue(ex.getMessage().startsWith("unable to unwrap key: OpenSSL Error:"),
                    "byte " + pos + ": unexpected message " + ex.getMessage());
            // Not "OpenSSL Error: null" — an EMPTY queue, which elsewhere in
            // this suite means an OPS-INJECTED failure. The wrap recovery
            // re-inits under a mark/pop pair precisely so it does not scrub
            // the refusal.
            Assertions.assertFalse(ex.getMessage().endsWith("null"),
                    "byte " + pos + ": the OpenSSL error queue was scrubbed by the recovery path");
        }

        byte[] wrongKek = Arrays.clone(kek);
        wrongKek[16] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap(FIPS, wrongKek, wrapped),
                "a wrong KEK must fail the integrity check");
    }

    /**
     * KEK and payload length boundaries against the module. The floors (two
     * semiblocks to wrap, three to unwrap) and the multiple-of-8 rule were
     * measured on both modules in {@code wrapinv_probe.c} Q4.
     */
    @Test
    public void lengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("lengthBoundaries");
        byte[] cek = new byte[16];
        sr.nextBytes(cek);

        for (int len : new int[]{15, 16, 17, 23, 24, 25, 31, 32, 33})
        {
            byte[] kek = new byte[len];
            sr.nextBytes(kek);
            boolean valid = (len == 16 || len == 24 || len == 32);

            if (valid)
            {
                Assertions.assertNotNull(wrap(FIPS, kek, cek), "KEK length " + len + " must be accepted");
            }
            else
            {
                Assertions.assertThrows(Exception.class, () -> wrap(FIPS, kek, cek),
                        "KEK length " + len + " must be rejected");
            }
        }

        byte[] kek = new byte[32];
        sr.nextBytes(kek);

        for (int len : new int[]{1, 8, 15, 17, 20})
        {
            byte[] shortCek = new byte[len];
            sr.nextBytes(shortCek);
            Assertions.assertThrows(Exception.class, () -> wrap(FIPS, kek, shortCek),
                    "payload length " + len + " must be rejected");
        }

        for (int len : new int[]{16, 24, 64})
        {
            byte[] okCek = new byte[len];
            sr.nextBytes(okCek);
            byte[] wrapped = wrap(FIPS, kek, okCek);
            Assertions.assertEquals(len + 8, wrapped.length, "payload length " + len + ": wrapped length");
            Assertions.assertTrue(Arrays.areEqual(okCek, unwrap(FIPS, kek, wrapped)),
                    "payload length " + len + ": round trip");
        }

        byte[] shortBlob = new byte[16];
        sr.nextBytes(shortBlob);
        Assertions.assertThrows(InvalidKeyException.class, () -> unwrap(FIPS, kek, shortBlob),
                "a 16-byte blob is below the unwrap floor");
    }

    /**
     * Reuse of one instance, checked against BC on EVERY operation rather than
     * against the instance's own earlier output. Both defects this catches
     * were live in the shared block-cipher context until WI-9 — a stale-IV
     * reset, and a failure that poisoned the context beyond recovery — and
     * self-consistency would have passed for both.
     */
    @Test
    public void oneInstanceStaysCorrectAcrossOperationsAndAfterFailure() throws Exception
    {
        SecureRandom sr = seededRandom("oneInstanceStaysCorrectAcrossOperationsAndAfterFailure");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);

        Cipher wrapper = Cipher.getInstance("AESWrapInv", FIPS);
        wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));

        byte[] first = null;
        byte[] firstCek = null;
        for (int i = 0; i < 4; i++)
        {
            byte[] cek = new byte[16 + 8 * i];
            sr.nextBytes(cek);
            byte[] mine = wrapper.wrap(new SecretKeySpec(cek, "AES"));
            if (i == 0)
            {
                first = mine;
                firstCek = cek;
            }
            Assertions.assertTrue(Arrays.areEqual(bcEngineWrap(kek, cek), mine),
                    "operation " + i + ": diverged from BouncyCastle on a reused instance");
        }

        Cipher unwrapper = Cipher.getInstance("AESWrapInv", FIPS);
        unwrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));

        byte[] damaged = Arrays.clone(first);
        damaged[0] ^= (byte) 0x01;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrapper.unwrap(damaged, "AES", Cipher.SECRET_KEY));

        // unwrap() THROWS on failure, so non-null asserts nothing: an instance
        // left corrupt that returned the WRONG key would pass. The test is named
        // for staying CORRECT — compare against the CEK that was wrapped.
        java.security.Key recovered = unwrapper.unwrap(first, "AES", Cipher.SECRET_KEY);
        Assertions.assertTrue(Arrays.areEqual(firstCek, recovered.getEncoded()),
                "the failed unwrap left the instance returning the wrong key");
    }

    /**
     * Key isolation does not apply (SecretKeys carry no native handle), but
     * the wrapped bytes must cross freely in both directions — that is the
     * whole point of a key-wrap interop surface.
     */
    @Test
    public void wrappedBlobsCrossBetweenProviders() throws Exception
    {
        SecureRandom sr = seededRandom("wrappedBlobsCrossBetweenProviders");
        byte[] kek = new byte[32];
        sr.nextBytes(kek);
        byte[] cek = new byte[32];
        sr.nextBytes(cek);

        Assertions.assertTrue(Arrays.areEqual(cek, unwrap(JSL, kek, wrap(FIPS, kek, cek))),
                "a JSLFIPS-wrapped blob did not read under JSL");
        Assertions.assertTrue(Arrays.areEqual(cek, unwrap(FIPS, kek, wrap(JSL, kek, cek))),
                "a JSL-wrapped blob did not read under JSLFIPS");
    }
}
