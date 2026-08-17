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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES key wrap (RFC 3394) and key wrap with padding (RFC 5649), delegated to
 * OpenSSL through JSL. Verified against a published RFC 3394 vector and against
 * BouncyCastle for interop, both resolved by NIST OID.
 */
public class AESKeyWrapTest
{
    // NIST AES key-wrap OIDs.
    private static final String AES128_WRAP = "2.16.840.1.101.3.4.1.5";
    private static final String AES192_WRAP = "2.16.840.1.101.3.4.1.25";
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";
    private static final String AES128_WRAP_PAD = "2.16.840.1.101.3.4.1.8";
    private static final String AES256_WRAP_PAD = "2.16.840.1.101.3.4.1.48";

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
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * RFC 3394 section 4.1: wrap 128 bits of key data with a 128-bit KEK.
     */
    @Test
    public void rfc3394Vector() throws Exception
    {
        byte[] kek = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] keyData = Hex.decode("00112233445566778899AABBCCDDEEFF");
        byte[] expected = Hex.decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

        Cipher wrap = Cipher.getInstance(AES128_WRAP, JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
        byte[] wrapped = wrap.wrap(new SecretKeySpec(keyData, "AES"));
        Assertions.assertArrayEquals(expected, wrapped, "RFC 3394 wrap vector mismatch");

        Cipher unwrap = Cipher.getInstance(AES128_WRAP, JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
        Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(keyData, recovered.getEncoded(), "RFC 3394 unwrap vector mismatch");
    }

    @Test
    public void kwRoundTripAllKekSizes() throws Exception
    {
        SecureRandom random = seededRandom("kwRoundTripAllKekSizes");
        String[] oids = {AES128_WRAP, AES192_WRAP, AES256_WRAP};
        int[] kekLens = {16, 24, 32};

        for (int i = 0; i < oids.length; i++)
        {
            byte[] kekBytes = new byte[kekLens[i]];
            random.nextBytes(kekBytes);
            Key kek = new SecretKeySpec(kekBytes, "AES");

            // wrap a 256-bit content key (multiple of 8, >= 16: valid KW input)
            byte[] cek = new byte[32];
            random.nextBytes(cek);

            Cipher wrap = Cipher.getInstance(oids[i], JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = wrap.wrap(new SecretKeySpec(cek, "AES"));
            Assertions.assertEquals(cek.length + 8, wrapped.length, "KW output must be input + 8");

            Cipher unwrap = Cipher.getInstance(oids[i], JostleProvider.PROVIDER_NAME);
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertArrayEquals(cek, recovered.getEncoded());
        }
    }

    @Test
    public void kwInteropWithBouncyCastle() throws Exception
    {
        SecureRandom random = seededRandom("kwInteropWithBouncyCastle");
        byte[] kekBytes = new byte[32];
        random.nextBytes(kekBytes);
        Key kek = new SecretKeySpec(kekBytes, "AES");
        byte[] cek = new byte[24];
        random.nextBytes(cek);

        Cipher jslWrap = Cipher.getInstance(AES256_WRAP, JostleProvider.PROVIDER_NAME);
        jslWrap.init(Cipher.WRAP_MODE, kek);
        byte[] jslWrapped = jslWrap.wrap(new SecretKeySpec(cek, "AES"));

        Cipher bcWrap = Cipher.getInstance(AES256_WRAP, BouncyCastleProvider.PROVIDER_NAME);
        bcWrap.init(Cipher.WRAP_MODE, kek);
        byte[] bcWrapped = bcWrap.wrap(new SecretKeySpec(cek, "AES"));

        if (!Arrays.areEqual(jslWrapped, bcWrapped))
        {
            System.out.println("JSL " + Hex.toHexString(jslWrapped));
            System.out.println("BC  " + Hex.toHexString(bcWrapped));
        }
        Assertions.assertArrayEquals(bcWrapped, jslWrapped, "JSL and BC AES-KW output differ");

        // cross-unwrap: BC unwraps JSL's output and vice versa
        Cipher bcUnwrap = Cipher.getInstance(AES256_WRAP, BouncyCastleProvider.PROVIDER_NAME);
        bcUnwrap.init(Cipher.UNWRAP_MODE, kek);
        Assertions.assertArrayEquals(cek, bcUnwrap.unwrap(jslWrapped, "AES", Cipher.SECRET_KEY).getEncoded());

        Cipher jslUnwrap = Cipher.getInstance(AES256_WRAP, JostleProvider.PROVIDER_NAME);
        jslUnwrap.init(Cipher.UNWRAP_MODE, kek);
        Assertions.assertArrayEquals(cek, jslUnwrap.unwrap(bcWrapped, "AES", Cipher.SECRET_KEY).getEncoded());
    }

    @Test
    public void kwpArbitraryLengthInteropWithBouncyCastle() throws Exception
    {
        SecureRandom random = seededRandom("kwpArbitraryLengthInteropWithBouncyCastle");
        byte[] kekBytes = new byte[32];
        random.nextBytes(kekBytes);
        Key kek = new SecretKeySpec(kekBytes, "AES");

        // KWP (RFC 5649) handles arbitrary lengths, including non-multiples of 8.
        for (int len : new int[]{1, 7, 20, 31})
        {
            byte[] data = new byte[len];
            random.nextBytes(data);

            Cipher jslWrap = Cipher.getInstance(AES256_WRAP_PAD, JostleProvider.PROVIDER_NAME);
            jslWrap.init(Cipher.WRAP_MODE, kek);
            byte[] jslWrapped = jslWrap.wrap(new SecretKeySpec(data, "AES"));

            Cipher bcWrap = Cipher.getInstance(AES256_WRAP_PAD, BouncyCastleProvider.PROVIDER_NAME);
            bcWrap.init(Cipher.WRAP_MODE, kek);
            byte[] bcWrapped = bcWrap.wrap(new SecretKeySpec(data, "AES"));
            Assertions.assertArrayEquals(bcWrapped, jslWrapped, "KWP output differs from BC for len=" + len);

            Cipher jslUnwrap = Cipher.getInstance(AES256_WRAP_PAD, JostleProvider.PROVIDER_NAME);
            jslUnwrap.init(Cipher.UNWRAP_MODE, kek);
            Key recovered = jslUnwrap.unwrap(jslWrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertArrayEquals(data, recovered.getEncoded(), "KWP round-trip failed for len=" + len);
        }
    }

    @Test
    public void kwRejectsNonAlignedInput() throws Exception
    {
        SecureRandom random = seededRandom("kwRejectsNonAlignedInput");
        byte[] kekBytes = new byte[32];
        random.nextBytes(kekBytes);
        Key kek = new SecretKeySpec(kekBytes, "AES");

        // 20 bytes is not a multiple of 8 -> invalid for plain KW (RFC 3394).
        byte[] data = new byte[20];
        random.nextBytes(data);

        Cipher wrap = Cipher.getInstance(AES256_WRAP, JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek);
        boolean rejected = false;
        try
        {
            wrap.wrap(new SecretKeySpec(data, "AES"));
        }
        catch (Exception e)
        {
            rejected = true;
        }
        Assertions.assertTrue(rejected, "plain KW must reject a non-multiple-of-8 input");
    }

    @Test
    public void tamperedWrappedKeyRejected() throws Exception
    {
        SecureRandom random = seededRandom("tamperedWrappedKeyRejected");
        byte[] kekBytes = new byte[32];
        random.nextBytes(kekBytes);
        Key kek = new SecretKeySpec(kekBytes, "AES");
        byte[] cek = new byte[16];
        random.nextBytes(cek);

        Cipher wrap = Cipher.getInstance(AES256_WRAP, JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = wrap.wrap(new SecretKeySpec(cek, "AES"));
        wrapped[0] ^= 0x01;

        Cipher unwrap = Cipher.getInstance(AES256_WRAP, JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kek);
        boolean rejected = false;
        try
        {
            unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        }
        catch (Exception e)
        {
            rejected = true;
        }
        Assertions.assertTrue(rejected, "tampered wrapped key must fail the integrity check");
    }

    /**
     * Key wrap resolves by NAME, not only by OID, and agrees with BC both
     * directions. The name registrations are key-size-agnostic, so the sweep
     * runs all three KEK sizes through one name; byte-equality against the OID
     * primary is what proves the name selects genuine RFC 3394 wrap.
     * "AESWRAP"/"aeswrap" need no registration (lookup is case-insensitive) —
     * included to pin that.
     */
    @Test
    public void wrapResolvesByName_andAgreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("wrapResolvesByName_andAgreesWithBC");
        String[] names = {"AESWrap", "AESWRAP", "aeswrap", "AESKW"};

        for (int kekLen : new int[]{16, 24, 32})
        {
            byte[] kekBytes = new byte[kekLen];
            sr.nextBytes(kekBytes);
            Key kek = new SecretKeySpec(kekBytes, "AES");
            byte[] cekBytes = new byte[32];
            sr.nextBytes(cekBytes);
            Key cek = new SecretKeySpec(cekBytes, "AES");

            // Reference: the already-working size-specific OID primary.
            String oid = (kekLen == 16) ? AES128_WRAP : (kekLen == 24) ? AES192_WRAP : AES256_WRAP;
            Cipher ref = Cipher.getInstance(oid, JostleProvider.PROVIDER_NAME);
            ref.init(Cipher.WRAP_MODE, kek);
            byte[] refWrapped = ref.wrap(cek);

            for (String name : names)
            {
                String where = name + "/kek" + kekLen;

                Cipher jslWrap = Cipher.getInstance(name, JostleProvider.PROVIDER_NAME);
                jslWrap.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = jslWrap.wrap(cek);
                Assertions.assertTrue(Arrays.areEqual(refWrapped, wrapped),
                        where + ": name did not wrap identically to the OID primary");

                // Jostle-wrap -> BC-unwrap.
                Cipher bcUnwrap = Cipher.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
                bcUnwrap.init(Cipher.UNWRAP_MODE, kek);
                Key bcRecovered = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
                Assertions.assertTrue(Arrays.areEqual(cekBytes, bcRecovered.getEncoded()),
                        where + ": JSL-wrap/BC-unwrap");

                // BC-wrap -> Jostle-unwrap.
                Cipher bcWrap = Cipher.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
                bcWrap.init(Cipher.WRAP_MODE, kek);
                byte[] bcWrapped = bcWrap.wrap(cek);
                Assertions.assertTrue(Arrays.areEqual(refWrapped, bcWrapped),
                        where + ": BC produced different wrapped bytes");

                Cipher jslUnwrap = Cipher.getInstance(name, JostleProvider.PROVIDER_NAME);
                jslUnwrap.init(Cipher.UNWRAP_MODE, kek);
                Key recovered = jslUnwrap.unwrap(bcWrapped, "AES", Cipher.SECRET_KEY);
                Assertions.assertTrue(Arrays.areEqual(cekBytes, recovered.getEncoded()),
                        where + ": BC-wrap/JSL-unwrap");
            }
        }
    }

    /**
     * KWP (RFC 5649) by name, agreeing with BC. The CEK length is not a
     * multiple of 8 — the case plain KW rejects — so this also proves the name
     * maps to the padded mode rather than WRAP.
     */
    @Test
    public void wrapPadResolvesByName_andAgreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("wrapPadResolvesByName_andAgreesWithBC");
        byte[] kekBytes = new byte[32];
        sr.nextBytes(kekBytes);
        Key kek = new SecretKeySpec(kekBytes, "AES");
        byte[] cekBytes = new byte[20];   // not a multiple of 8
        sr.nextBytes(cekBytes);
        Key cek = new SecretKeySpec(cekBytes, "AES");

        Cipher ref = Cipher.getInstance(AES256_WRAP_PAD, JostleProvider.PROVIDER_NAME);
        ref.init(Cipher.WRAP_MODE, kek);
        byte[] refWrapped = ref.wrap(cek);

        for (String name : new String[]{"AESWrapPad", "AESKWP"})
        {
            Cipher jslWrap = Cipher.getInstance(name, JostleProvider.PROVIDER_NAME);
            jslWrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = jslWrap.wrap(cek);
            Assertions.assertTrue(Arrays.areEqual(refWrapped, wrapped),
                    name + ": did not wrap identically to the OID primary");

            Cipher jslUnwrap = Cipher.getInstance(name, JostleProvider.PROVIDER_NAME);
            jslUnwrap.init(Cipher.UNWRAP_MODE, kek);
            Key recovered = jslUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertTrue(Arrays.areEqual(cekBytes, recovered.getEncoded()),
                    name + ": round trip");

            Cipher bcWrap = Cipher.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
            bcWrap.init(Cipher.WRAP_MODE, kek);
            Assertions.assertTrue(Arrays.areEqual(refWrapped, bcWrap.wrap(cek)),
                    name + ": BC produced different wrapped bytes");
        }
    }

    /**
     * Transformation form: "AES/KW/NoPadding" and "AES/KWP/NoPadding" reach the
     * bare "AES" primary via JCE form-4 lookup, where engineSetMode maps KW /
     * KWP onto WRAP / WRAP_PAD. Output must match the matching OID primary.
     */
    @Test
    public void kwTransformationNamesResolve() throws Exception
    {
        SecureRandom sr = seededRandom("kwTransformationNamesResolve");
        byte[] kekBytes = new byte[32];
        sr.nextBytes(kekBytes);
        Key kek = new SecretKeySpec(kekBytes, "AES");
        byte[] cekBytes = new byte[16];
        sr.nextBytes(cekBytes);
        Key cek = new SecretKeySpec(cekBytes, "AES");

        Cipher refKw = Cipher.getInstance(AES256_WRAP, JostleProvider.PROVIDER_NAME);
        refKw.init(Cipher.WRAP_MODE, kek);
        byte[] kwExpected = refKw.wrap(cek);

        Cipher kw = Cipher.getInstance("AES/KW/NoPadding", JostleProvider.PROVIDER_NAME);
        kw.init(Cipher.WRAP_MODE, kek);
        Assertions.assertTrue(Arrays.areEqual(kwExpected, kw.wrap(cek)), "AES/KW/NoPadding");

        Cipher refKwp = Cipher.getInstance(AES256_WRAP_PAD, JostleProvider.PROVIDER_NAME);
        refKwp.init(Cipher.WRAP_MODE, kek);
        byte[] kwpExpected = refKwp.wrap(cek);

        Cipher kwp = Cipher.getInstance("AES/KWP/NoPadding", JostleProvider.PROVIDER_NAME);
        kwp.init(Cipher.WRAP_MODE, kek);
        Assertions.assertTrue(Arrays.areEqual(kwpExpected, kwp.wrap(cek)), "AES/KWP/NoPadding");

        // KW and KWP are genuinely different modes, so the two must differ —
        // proving the alias mapping does not collapse them onto one mode.
        Assertions.assertFalse(Arrays.areEqual(kwExpected, kwpExpected),
                "KW and KWP must not produce identical output");
    }
}
