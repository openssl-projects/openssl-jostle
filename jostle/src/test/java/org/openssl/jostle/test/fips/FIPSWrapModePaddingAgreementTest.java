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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.test.crypto.WrapModeTransformationGuard;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The JSLFIPS half of WrapModePaddingAgreementTest: on the AES wrap modes, NoPadding gives the dedicated name's
 * bytes and every other padding name is refused, naming the mode.
 */
public class FIPSWrapModePaddingAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[][] SPELLINGS = {
        {"WRAP", "WRAP", "AESWrap"}, {"KW", "WRAP", "AESWrap"},
        {"WRAP_PAD", "WRAP_PAD", "AESWrapPad"}, {"KWP", "WRAP_PAD", "AESWrapPad"},
        {"WRAP_INV", "WRAP_INV", "AESWrapInv"}, {"KWINV", "WRAP_INV", "AESWrapInv"},
        {"WRAP-INV", "WRAP_INV", "AESWrapInv"}};

    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    private static byte[] wrap(String transformation, byte[] key, byte[] in) throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, fips);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(in);
    }

    @Test
    public void noPaddingEqualsTheDedicatedNameAndEveryOtherPaddingIsRefused() throws Exception
    {
        for (String[] s : SPELLINGS)
        {
            byte[] key = new byte[16 + 8 * RANDOM.nextInt(3)];
            RANDOM.nextBytes(key);
            byte[] in = new byte[24];
            RANDOM.nextBytes(in);
            String t = "AES/" + s[0] + "/NoPadding";
            Assertions.assertArrayEquals(wrap(s[2], key, in), wrap(t, key, in), t);
            for (String padding : new String[]{"PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "FooPadding"})
            {
                String p = "AES/" + s[0] + "/" + padding;
                NoSuchPaddingException e = assertThrows(NoSuchPaddingException.class,
                        () -> Cipher.getInstance(p, fips), p);
                Assertions.assertEquals("key wrap mode " + s[1] + " takes no padding", e.getMessage(), p);
            }
        }
        NoSuchPaddingException e = assertThrows(NoSuchPaddingException.class,
                () -> Cipher.getInstance("AESWrap/KW/PKCS5Padding", fips));
        Assertions.assertEquals("key wrap mode WRAP takes no padding", e.getMessage());
    }

    @Test
    public void noServiceRegistersAWrapModeTransformation()
    {
        WrapModeTransformationGuard.assertNone(fips);
    }
}
