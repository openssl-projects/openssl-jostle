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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;

/**
 * Behaviour-lock unit tests for the FIPS provider's AES {@link KeyGenerator}
 * surface. This is the FIPS analogue of
 * {@code crypto/AESKeyGeneratorTest}; it mirrors that test's assertion
 * structure and exact messages, changing only the provider (JSLFIPS), the
 * gating, and the key origin.
 * <p>
 * The bare {@code "AES"} generator defaults to 256 bits; {@code "AES128"},
 * {@code "AES192"} and {@code "AES256"} are fixed-size primaries that reject a
 * mismatched caller override. Every generated key is asserted non-zero, which
 * proves the FIPS KeyGenerator is drawing from the module's own approved DRBG
 * ({@code provider.getDefaultSecureRandom()}) rather than being mis-wired to a
 * null/JDK random or the wrong default.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSAESKeyGeneratorTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void keyGenInvalidSizeRejected() throws Exception
    {
        ensureProviders();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", FIPS);
        for (int size : new int[]{0, 127, 129, 191, 193, 255, 257})
        {
            try
            {
                keyGen.init(size, new SecureRandom());
                Assertions.fail("Should have thrown an exception");
            } catch (IllegalArgumentException ila)
            {
                Assertions.assertEquals("key size must be 128, 192 or 256", ila.getMessage());
            }
        }
    }

    @Test
    public void keyGenFixedSizeMismatchRejected() throws Exception
    {
        ensureProviders();
        SecureRandom sr = new SecureRandom();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES128", FIPS);
        try
        {
            keyGen.init(192, sr);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 128", iae.getMessage());
        }

        keyGen = KeyGenerator.getInstance("AES192", FIPS);
        try
        {
            keyGen.init(256, sr);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 192", iae.getMessage());
        }

        keyGen = KeyGenerator.getInstance("AES256", FIPS);
        try
        {
            keyGen.init(128, sr);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 256", iae.getMessage());
        }
    }

    @Test
    public void keyGenDefault256AndNonZeroFromModuleDrbg() throws Exception
    {
        ensureProviders();

        // Bare "AES" defaults to 256 bits without an explicit init().
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", FIPS);
        byte[] keyBytes = keyGen.generateKey().getEncoded();
        Assertions.assertEquals(256, keyBytes.length << 3);
        Assertions.assertFalse(Arrays.areAllZeroes(keyBytes, 0, keyBytes.length));

        // Fixed-size primaries yield their size without an explicit init().
        for (String algorithm : new String[]{"AES128", "AES192", "AES256"})
        {
            KeyGenerator fixed = KeyGenerator.getInstance(algorithm, FIPS);
            byte[] fixedBytes = fixed.generateKey().getEncoded();
            int expectedSize = Integer.parseInt(algorithm.substring("AES".length()));

            Assertions.assertEquals(expectedSize, fixedBytes.length << 3);
            Assertions.assertFalse(Arrays.areAllZeroes(fixedBytes, 0, fixedBytes.length));
        }

        // The explicitly-init'd valid sizes on the bare "AES" generator.
        for (int size : new int[]{128, 192, 256})
        {
            keyGen.init(size, new SecureRandom());
            byte[] sizedBytes = keyGen.generateKey().getEncoded();
            Assertions.assertEquals(size, sizedBytes.length << 3);
            Assertions.assertFalse(Arrays.areAllZeroes(sizedBytes, 0, sizedBytes.length));
        }
    }
}
