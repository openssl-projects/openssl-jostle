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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.cert.ProviderRegistrySnapshot;
import org.openssl.jostle.util.Arrays;
import org.opentest4j.AssertionFailedError;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A key-wrap mode reached by transformation on a plain cipher takes NoPadding only: every other padding name is
 * refused rather than accepted and not applied. NoPadding gives the dedicated wrap name's result, and the JDK's
 * and BouncyCastle's behaviour for the same strings is pinned beside ours.
 */
public class WrapModePaddingAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Every spelling that reaches a wrap mode, the mode it reaches, and the dedicated AES name for that mode. */
    static final String[][] SPELLINGS = {
        {"WRAP", "WRAP", "AESWrap"}, {"KW", "WRAP", "AESWrap"},
        {"WRAP_PAD", "WRAP_PAD", "AESWrapPad"}, {"KWP", "WRAP_PAD", "AESWrapPad"},
        {"WRAP_INV", "WRAP_INV", "AESWrapInv"}, {"KWINV", "WRAP_INV", "AESWrapInv"},
        {"WRAP-INV", "WRAP_INV", "AESWrapInv"}};

    static final String[] PADDINGS = {"PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "FooPadding"};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] wrap(String transformation, Provider p, byte[] key, String keyAlg, byte[] in) throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, p);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keyAlg));
        return c.doFinal(in);
    }

    /** Every AES spelling with NoPadding gives the dedicated name's bytes, for every key size; BC serves none. */
    @Test
    public void noPaddingOnEveryAesSpellingEqualsTheDedicatedName() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        int checked = 0;
        for (String[] s : SPELLINGS)
        {
            for (int keyLen : new int[]{16, 24, 32})
            {
                byte[] key = random(keyLen);
                byte[] in = random(24);
                String t = "AES/" + s[0] + "/NoPadding";
                Assertions.assertArrayEquals(wrap(s[2], jsl, key, "AES", in), wrap(t, jsl, key, "AES", in),
                        t + " key " + keyLen);
                checked++;
            }
            String t = "AES/" + s[0] + "/NoPadding";
            assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance(t, BC), "BC " + t);
        }
        Assertions.assertEquals(SPELLINGS.length * 3, checked);
    }

    /** Every padding name on every wrap spelling is refused, naming the mode, for every plain cipher family. */
    @Test
    public void everyPaddingNameOnAWrapModeIsRefused() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        int checked = 0;
        for (String family : new String[]{"AES", "DESede", "ARIA", "Camellia", "SM4"})
        {
            for (String[] s : SPELLINGS)
            {
                for (String padding : PADDINGS)
                {
                    String t = family + "/" + s[0] + "/" + padding;
                    NoSuchPaddingException e = assertThrows(NoSuchPaddingException.class,
                            () -> Cipher.getInstance(t, jsl), t);
                    Assertions.assertEquals("key wrap mode " + s[1] + " takes no padding", e.getMessage(), t);
                    checked++;
                }
            }
        }
        Assertions.assertEquals(5 * SPELLINGS.length * PADDINGS.length, checked);
    }

    /**
     * A dedicated wrap name given a padded transformation is refused as the JDK refuses it; the bare name and its
     * NoPadding form still work.
     */
    @Test
    public void aDedicatedWrapNameWithAPaddedTransformationIsRefused() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        String[][] cells = {{"AESWrap/WRAP/PKCS5Padding", "WRAP"}, {"AESWrap/KW/PKCS5Padding", "WRAP"},
            {"AESWrapPad/KWP/PKCS5Padding", "WRAP_PAD"}, {"AESWrapInv/KWINV/PKCS5Padding", "WRAP_INV"},
            {"DESedeWrap/WRAP/PKCS5Padding", "WRAP"}};
        for (String[] c : cells)
        {
            NoSuchPaddingException e = assertThrows(NoSuchPaddingException.class,
                    () -> Cipher.getInstance(c[0], jsl), c[0]);
            Assertions.assertEquals("key wrap mode " + c[1] + " takes no padding", e.getMessage(), c[0]);
        }
        byte[] key = random(16);
        byte[] in = random(24);
        Assertions.assertArrayEquals(wrap("AESWrap", jsl, key, "AES", in),
                wrap("AESWrap/KW/NoPadding", jsl, key, "AES", in));

        Provider sun = Security.getProvider("SunJCE");
        if (sun != null && sun.getService("Cipher", "AES/KW/NoPadding") != null)
        {
            NoSuchPaddingException jdk = assertThrows(NoSuchPaddingException.class,
                    () -> Cipher.getInstance("AESWrap/KW/PKCS5Padding", sun));
            Assertions.assertEquals("Unsupported padding PKCS5Padding", jdk.getMessage());
        }
    }

    /** The running JDK's major version: 8 for "1.8", 17 for "17". */
    private static int jdkMajor()
    {
        String spec = System.getProperty("java.specification.version");
        return Integer.parseInt(spec.startsWith("1.") ? spec.substring(2) : spec);
    }

    /**
     * The JDK's AES/KW/PKCS5Padding pads before wrapping, so it is a different algorithm from KW: absent before
     * JDK 17; from 17 it takes a 20-byte input KW refuses, and its output for 16 and 24 bytes is not KW's. Ours
     * refuses the name. The per-release lengths are recorded, not pinned.
     */
    @Test
    public void theJdksPaddedKwIsADifferentAlgorithmAndOursIsRefused() throws Exception
    {
        NoSuchPaddingException ours = assertThrows(NoSuchPaddingException.class,
                () -> Cipher.getInstance("AES/KW/PKCS5Padding", JSL));
        Assertions.assertEquals("key wrap mode WRAP takes no padding", ours.getMessage());

        Provider sun = Security.getProvider("SunJCE");
        Assumptions.assumeTrue(sun != null, "no SunJCE provider");
        if (jdkMajor() < 17)
        {
            assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance("AES/KW/PKCS5Padding", sun));
            return;
        }
        Provider jsl = Security.getProvider(JSL);
        byte[] key = random(16);
        byte[] twenty = random(20);
        Assertions.assertTrue(wrap("AES/KW/PKCS5Padding", sun, key, "AES", twenty).length > 20);
        assertThrows(IllegalBlockSizeException.class, () -> wrap("AESWrap", jsl, key, "AES", twenty));
        for (int len : new int[]{16, 24})
        {
            byte[] in = random(len);
            Assertions.assertFalse(Arrays.areEqual(wrap("AESWrap", jsl, key, "AES", in),
                    wrap("AES/KW/PKCS5Padding", sun, key, "AES", in)), "the padded name is not KW, in " + len);
        }
    }

    /**
     * With JSL first and no provider named, the name JSL now refuses falls through: below JDK 17 nothing serves it,
     * and from 17 the JDK's padded KW answers. Ordinary JCA resolution, recorded because the bytes change.
     */
    @Test
    public void anUnqualifiedPaddedKwNameIsNotServedByJsl() throws Exception
    {
        try (ProviderRegistrySnapshot ignored = new ProviderRegistrySnapshot())
        {
            ProviderRegistrySnapshot.insertFirst(Security.getProvider(JSL));
            if (jdkMajor() < 17)
            {
                assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance("AES/KW/PKCS5Padding"));
            }
            else
            {
                Assertions.assertNotEquals(JSL, Cipher.getInstance("AES/KW/PKCS5Padding").getProvider().getName());
            }
        }
    }

    /**
     * No service registers a wrap mode as a transformation, so the JCE always sets the mode before the padding and
     * the refusal in engineSetPadding sees it.
     */
    @Test
    public void noServiceRegistersAWrapModeTransformation()
    {
        WrapModeTransformationGuard.assertNone(Security.getProvider(JSL));
    }

    /** A synthetic provider for the guard's own check; it serves nothing. */
    private static final class Synthetic extends Provider
    {
        Synthetic(String... entries)
        {
            super("Synthetic", 1.0, "guard check");
            for (int i = 0; i < entries.length; i += 2)
            {
                put(entries[i], entries[i + 1]);
            }
        }
    }

    /**
     * The guard fires on a wrap mode registered inside a transformation, on an alias of that shape, and on any
     * empty-mode "X//Padding" form (plain and dedicated names alike), and fails as vacuous on a provider with no
     * Cipher alias; it stays silent on transformations with a non-wrap mode.
     */
    @Test
    public void theGuardFiresOnEachShapeAndStaysSilentOtherwise()
    {
        Provider[] bad = {
            new Synthetic("Cipher.AES/KW/NoPadding", "x.Spi", "Alg.Alias.Cipher.AES", "AESX"),
            new Synthetic("Cipher.AES", "x.Spi", "Alg.Alias.Cipher.AES/WRAP_PAD/NoPadding", "AES"),
            new Synthetic("Cipher.AES", "x.Spi", "Alg.Alias.Cipher.AES//PKCS5Padding", "AES"),
            new Synthetic("Cipher.DESede/WRAP/NoPadding", "x.Spi", "Alg.Alias.Cipher.TripleDES", "DESede"),
            new Synthetic("Cipher.AES/CBC/NoPadding", "x.Spi"),
            new Synthetic("Cipher.AESWrap", "x.Spi", "Alg.Alias.Cipher.AESWrap//PKCS5Padding", "AESWrap"),
            new Synthetic("Cipher.DESedeWrap//NoPadding", "x.Spi", "Alg.Alias.Cipher.TDEAWrap", "DESedeWrap"),
            new Synthetic("Cipher.ARIA", "x.Spi", "Alg.Alias.Cipher.ARIA//PKCS5Padding", "ARIA")};
        for (Provider p : bad)
        {
            Assertions.assertThrows(AssertionFailedError.class, () -> WrapModeTransformationGuard.assertNone(p),
                    p.keySet().toString());
        }
        WrapModeTransformationGuard.assertNone(new Synthetic("Cipher.AES/CBC/NoPadding", "x.Spi",
                "Alg.Alias.Cipher.AES/GCM/NoPadding", "AES", "Alg.Alias.Cipher.AESWrap/WRAPPER/X", "AESWrap"));
    }
}
