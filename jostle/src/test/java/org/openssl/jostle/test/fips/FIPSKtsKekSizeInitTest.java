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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import javax.crypto.Cipher;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

/**
 * The JSLFIPS twin of {@code KtsKekSizeInitTest}: the module's KTS ciphers refuse a KEK size AES key wrap cannot
 * take at init, on wrap and unwrap, for each KTS cipher the loaded module registers.
 */
public class FIPSKtsKekSizeInitTest
{
    private static JostleFIPSProvider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    private static void refusedAtInit(String cipher, int mode, Key key, KTSParameterSpec spec, String message)
        throws Exception
    {
        final Cipher c = Cipher.getInstance(cipher, fips);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(mode, key, spec), cipher + " mode " + mode + " " + spec.getKeySize() + " bits");
        Assertions.assertEquals(message, e.getMessage());
    }

    @Test
    public void aKekSizeAesKeyWrapCannotTakeIsRefusedAtInit() throws Exception
    {
        List<String> ran = new ArrayList<String>();
        String[][] ciphers = {{"ML-KEM", "ML-KEM-768"}, {"RSA-KTS-KEM-KWS", "RSA"}};
        for (String[] c : ciphers)
        {
            if (fips.getService("Cipher", c[0]) == null || fips.getService("KeyPairGenerator", c[1]) == null)
            {
                continue;
            }
            KeyPairGenerator g = KeyPairGenerator.getInstance(c[1], fips);
            if ("RSA".equals(c[1]))
            {
                g.initialize(2048);
            }
            KeyPair kp = g.generateKeyPair();
            for (int bits : new int[]{127, 136, 257, 512})
            {
                String message = "unsupported AES-KW KEK size: " + bits + " bits; AES key wrap takes 128, 192 or 256";
                refusedAtInit(c[0], Cipher.WRAP_MODE, kp.getPublic(),
                        new KTSParameterSpec.Builder("AESWRAP", bits).build(), message);
                refusedAtInit(c[0], Cipher.UNWRAP_MODE, kp.getPrivate(),
                        new KTSParameterSpec.Builder("AESWRAP", bits).withNoKdf().build(), message);
            }
            ran.add(c[0]);
        }
        Assertions.assertTrue(ran.contains("RSA-KTS-KEM-KWS"), "the module serves no RSA KTS cipher: " + ran);
    }
}
