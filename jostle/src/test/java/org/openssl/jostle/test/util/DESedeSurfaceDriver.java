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

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

/**
 * Drives one registered Triple-DES service, for both providers' guards.
 *
 * <p>Shared because the two registrars use the same SPI class-name prefix and
 * the same names, so a per-class copy would be two things to keep in step.
 */
public final class DESedeSurfaceDriver
{
    private DESedeSurfaceDriver()
    {
    }

    public static ProviderSurfaceGuard.ServiceDriver forProvider(final String provider)
    {
        return new ProviderSurfaceGuard.ServiceDriver()
        {
            public void drive(String type, String alg) throws Exception
            {
                SecureRandom sr = new SecureRandom();
                if ("KeyGenerator".equals(type))
                {
                    Assertions.assertNotNull(
                            KeyGenerator.getInstance(alg, provider).generateKey(), alg);
                    return;
                }
                if (!"Cipher".equals(type))
                {
                    throw new IllegalStateException("no drive defined for " + type + "." + alg
                            + " — teach this driver rather than letting it go unexercised");
                }

                byte[] keyBytes = new byte[24];
                sr.nextBytes(keyBytes);
                SecretKey key = new SecretKeySpec(keyBytes, "DESede");
                byte[] msg = new byte[32];
                sr.nextBytes(msg);

                Cipher enc = Cipher.getInstance(alg, provider);
                try
                {
                    enc.init(Cipher.ENCRYPT_MODE, key, sr);
                }
                catch (InvalidKeyException e)
                {
                    // tdes-encrypt-disabled is a fipsinstall switch: the module
                    // may refuse encryption while still decrypting. Accepted
                    // only with its own pinned message, so a refusal for any
                    // other reason still fails the guard.
                    Assertions.assertTrue(
                            String.valueOf(e.getMessage()).contains("Triple-DES encryption is not supported"),
                            alg + ": refused, but not by the tdes-encrypt-disabled gate: " + e.getMessage());
                    Cipher dec = Cipher.getInstance(alg, provider);
                    dec.init(Cipher.DECRYPT_MODE, key, enc.getParameters());
                    return;
                }

                byte[] ct = enc.doFinal(msg);
                Cipher dec = Cipher.getInstance(alg, provider);
                dec.init(Cipher.DECRYPT_MODE, key, enc.getParameters());
                Assertions.assertArrayEquals(msg, dec.doFinal(ct), alg + ": round trip");
            }
        };
    }
}
