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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Random number generators backed by OpenSSL's DRBGs. The mechanism-named variants (`CTR-DRBG-AES256`,
 * `HASH-DRBG-SHA512`, `HMAC-DRBG-SHA256`, ...) pin the DRBG and its security strength.
 */
public class SecureRandomExamplesTest
        extends JslExamples
{
    /**
     * Draw random bytes from JSL's default generator. Two draws of the same length differ.
     */
    @Test
    public void defaultGenerator()
            throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "JSL");
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        random.nextBytes(a);
        random.nextBytes(b);
        Assertions.assertFalse(Arrays.equals(a, b));
    }

    /**
     * Pick a specific DRBG mechanism by name. Each seeds itself; `setSeed` adds caller material to it.
     */
    @Test
    public void everyDrbg()
            throws Exception
    {
        String[] names = {"DRBG", "CTR-DRBG", "CTR-DRBG-AES128", "CTR-DRBG-AES192", "CTR-DRBG-AES256",
                "HASH-DRBG", "HASH-DRBG-SHA1", "HASH-DRBG-SHA224", "HASH-DRBG-SHA256", "HASH-DRBG-SHA384",
                "HASH-DRBG-SHA512", "HMAC-DRBG", "HMAC-DRBG-SHA1", "HMAC-DRBG-SHA224", "HMAC-DRBG-SHA256",
                "HMAC-DRBG-SHA384", "HMAC-DRBG-SHA512"};
        for (String name : names)
        {
            SecureRandom random = SecureRandom.getInstance(name, "JSL");
            random.setSeed(new byte[]{1, 2, 3});
            byte[] a = new byte[48];
            byte[] b = new byte[48];
            random.nextBytes(a);
            random.nextBytes(b);
            Assertions.assertFalse(Arrays.equals(a, b), name);
        }
    }
}
