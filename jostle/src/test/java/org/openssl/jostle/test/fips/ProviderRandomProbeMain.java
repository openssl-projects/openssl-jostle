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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.JvmProbe;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;

/**
 * Reports how {@code org.openssl.jostle.fips.enforce_provider_random} resolved in this JVM,
 * and - when a FIPS module is configured - what the FIPS AES KeyGenerator does with a
 * caller-supplied, non-provider SecureRandom under that setting.
 * <p>
 * Not a test. This is the entry point {@code FIPSProviderRandomPropertyIntegrationTest}
 * launches in a fresh JVM: the property is read once into a {@code static final} field during
 * {@link CryptoServicesRegistrar} initialisation, so it can only be exercised at start-up.
 * <p>
 * Takes the SHA1PRNG seed as {@code args[0]} so the parent owns it and can report it on
 * failure. The class name deliberately avoids "Test" so no JUnit filter picks it up.
 */
public final class ProviderRandomProbeMain
{
    private ProviderRandomProbeMain()
    {
    }

    public static void main(String[] args) throws Exception
    {
        JvmProbe.emit("providerRandomEnforced",
                String.valueOf(CryptoServicesRegistrar.isProviderRandomEnforced()));

        //
        // Driven by TEST_FIPS_LIB, which the child inherits from the parent's environment.
        // Absent it there is no module to key off and only the flag above is reportable.
        //
        JostleFIPSProvider provider = TestUtil.addFipsProvider();
        if (provider == null)
        {
            JvmProbe.emit("fipsAvailable", "false");
            return;
        }
        JvmProbe.emit("fipsAvailable", "true");

        long seed = Long.parseLong(args[0]);
        JvmProbe.emit("key.0", toHex(generateKeyWithSeededRandom(seed)));
        JvmProbe.emit("key.1", toHex(generateKeyWithSeededRandom(seed)));
    }

    /**
     * Generates a 256-bit AES key from the FIPS provider, offering it a SHA1PRNG seeded to a
     * known value. Whether that random actually determines the key is the whole question:
     * enforced, the module DRBG overrides it; not enforced, it is honoured verbatim.
     */
    private static byte[] generateKeyWithSeededRandom(long seed) throws Exception
    {
        SecureRandom seeded = SecureRandom.getInstance("SHA1PRNG");
        seeded.setSeed(seed);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", JostleFIPSProvider.PROVIDER_NAME);
        keyGen.init(256, seeded);
        return keyGen.generateKey().getEncoded();
    }

    private static String toHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data)
        {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
