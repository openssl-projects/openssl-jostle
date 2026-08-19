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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * SecureRandom and KeyGenerator through the FIPS provider ("JSLFIPS"): every
 * registered DRBG produces output (chained to the FIPS module's own primary
 * DRBG), distinct calls and instances diverge, reseeding works, and AES keys
 * generated from the module DRBG interoperate. Gated on TEST_FIPS_LIB;
 * skipped when unset.
 */
public class FIPSRandTest
{
    // The FIPS-approved DRBG set: CTR-DRBG (all AES sizes) plus HASH-/HMAC-DRBG
    // over the FIPS 140-3 IG D.R digests (SHA-1, SHA2-256, SHA2-512). The
    // truncated-digest variants (SHA-224, SHA-384) are not registered by
    // ProvFIPSRand - see drbgsNotServedByModuleRejected.
    private static final String[] DRBGS = {
            "DRBG", "DEFAULT",
            "CTR-DRBG", "CTR-DRBG-AES128", "CTR-DRBG-AES192", "CTR-DRBG-AES256",
            "HASH-DRBG", "HASH-DRBG-SHA1", "HASH-DRBG-SHA256", "HASH-DRBG-SHA512",
            "HMAC-DRBG", "HMAC-DRBG-SHA1", "HMAC-DRBG-SHA256", "HMAC-DRBG-SHA512"
    };

    private static final String[] NOT_SERVED_DRBGS = {
            "HASH-DRBG-SHA224", "HASH-DRBG-SHA384",
            "HMAC-DRBG-SHA224", "HMAC-DRBG-SHA384"
    };

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static boolean allZero(byte[] bytes)
    {
        for (byte b : bytes)
        {
            if (b != 0)
            {
                return false;
            }
        }
        return true;
    }

    @Test
    public void drbgsProduceDivergingOutput()
        throws Exception
    {
        ensureProviders();

        for (String name : DRBGS)
        {
            SecureRandom random = SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);

            byte[] first = new byte[64];
            random.nextBytes(first);
            Assertions.assertFalse(allZero(first), name + ": all-zero output");

            byte[] second = new byte[64];
            random.nextBytes(second);
            Assertions.assertFalse(Arrays.equals(first, second),
                    name + ": consecutive calls produced identical output");

            // Reseeding (setSeed = additional input / reseed) must not break
            // the instance.
            random.setSeed(first);
            random.nextBytes(second);
            Assertions.assertFalse(allZero(second), name + ": output after setSeed");

            // Distinct instances diverge.
            SecureRandom other = SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            byte[] third = new byte[64];
            other.nextBytes(third);
            Assertions.assertFalse(Arrays.equals(second, third),
                    name + ": distinct instances produced identical output");
        }
    }

    @Test
    public void drbgsNotServedByModuleRejected()
        throws Exception
    {
        ensureProviders();

        for (String name : NOT_SERVED_DRBGS)
        {
            Assertions.assertThrows(java.security.NoSuchAlgorithmException.class,
                    () -> SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " (truncated DRBG digest) must not resolve through JSLFIPS");
        }
    }

    @Test
    public void largeRequestSpansChunks()
        throws Exception
    {
        ensureProviders();

        // Larger than the DRBG max-request boundary, so the native loop chunks.
        SecureRandom random = SecureRandom.getInstance("DEFAULT", JostleFIPSProvider.PROVIDER_NAME);
        byte[] big = new byte[70000];
        random.nextBytes(big);
        Assertions.assertFalse(allZero(Arrays.copyOfRange(big, big.length - 64, big.length)),
                "tail of a chunked request must be filled");
    }

    @Test
    public void keyGeneratorDrawsWorkingAesKeys()
        throws Exception
    {
        ensureProviders();

        // Default size (256) without init.
        KeyGenerator kg = KeyGenerator.getInstance("AES", JostleFIPSProvider.PROVIDER_NAME);
        SecretKey key = kg.generateKey();
        Assertions.assertEquals(32, key.getEncoded().length);

        // Explicit sizes.
        for (int size : new int[]{128, 192, 256})
        {
            kg.init(size);
            Assertions.assertEquals(size / 8, kg.generateKey().getEncoded().length);
        }

        // Fixed-size registration + distinct keys per call.
        KeyGenerator kg128 = KeyGenerator.getInstance("AES128", JostleFIPSProvider.PROVIDER_NAME);
        SecretKey k1 = kg128.generateKey();
        SecretKey k2 = kg128.generateKey();
        Assertions.assertEquals(16, k1.getEncoded().length);
        Assertions.assertFalse(Arrays.equals(k1.getEncoded(), k2.getEncoded()),
                "consecutive generated keys must differ");

        // The generated key is a normal AES key: JSLFIPS GCM encrypt with it,
        // BC decrypts.
        SecureRandom random = SecureRandom.getInstance("DEFAULT", JostleFIPSProvider.PROVIDER_NAME);
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        byte[] message = new byte[256];
        random.nextBytes(message);
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ct = enc.doFinal(message);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, spec);
        Assertions.assertArrayEquals(message, dec.doFinal(ct),
                "JSLFIPS-generated key must interoperate");
    }

    @Test
    public void fipsSecureRandomRegistrationSurfaceIsLocked()
    {
        ensureProviders();

        Provider provider = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);

        // Exactly the 14 approved DRBG names (plus DEFAULT alias) must resolve.
        for (String name : DRBGS)
        {
            Assertions.assertNotNull(provider.getService("SecureRandom", name),
                    name + " must be a registered SecureRandom service");
        }

        // The truncated-digest DRBGs must be filtered out by isFipsApproved.
        for (String name : NOT_SERVED_DRBGS)
        {
            Assertions.assertNull(provider.getService("SecureRandom", name),
                    name + " (truncated DRBG digest) must not be registered");
        }

        // JDK-default SecureRandom algorithms must never leak into JSLFIPS.
        Assertions.assertNull(provider.getService("SecureRandom", "SHA1PRNG"));
        Assertions.assertNull(provider.getService("SecureRandom", "NativePRNG"));
        Assertions.assertNull(provider.getService("SecureRandom", "NativePRNGNonBlocking"));
        Assertions.assertNull(provider.getService("SecureRandom", "DefaultRandom"));
    }

    @Test
    public void drbgThreadSafeAttribute()
    {
        ensureProviders();

        Provider provider = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);

        // ProvFIPSRand registers every DRBG ThreadSafe so the JCE does not
        // serialize access to the native EVP_RAND_CTX.
        Assertions.assertEquals("true", provider.get("SecureRandom.DRBG ThreadSafe"));
    }

    @Test
    public void generateSeedReturnsRequestedLengthAndRejectsNegative()
        throws Exception
    {
        ensureProviders();

        SecureRandom random = SecureRandom.getInstance("DRBG", JostleFIPSProvider.PROVIDER_NAME);

        byte[] seed = random.generateSeed(14);
        Assertions.assertEquals(14, seed.length);

        Assertions.assertThrows(IllegalArgumentException.class, () -> random.generateSeed(-1));
    }

    @Test
    public void nextBytesRejectsNull()
        throws Exception
    {
        ensureProviders();

        SecureRandom random = SecureRandom.getInstance("DRBG", JostleFIPSProvider.PROVIDER_NAME);

        Assertions.assertThrows(NullPointerException.class, () -> random.nextBytes(null));
    }

    @Test
    public void serializationIsNotSupported()
        throws Exception
    {
        ensureProviders();

        // A native-backed DRBG instance holds an EVP_RAND_CTX handle that cannot
        // be persisted, so serialization is deliberately forbidden: writeObject
        // throws and SecureRandom serialization fails deterministically.
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleFIPSProvider.PROVIDER_NAME);
        ObjectOutputStream objectOut = new ObjectOutputStream(new ByteArrayOutputStream());

        Throwable thrown = Assertions.assertThrows(Throwable.class, () -> objectOut.writeObject(random));

        Throwable root = thrown;
        while (root.getCause() != null)
        {
            root = root.getCause();
        }
        Assertions.assertTrue(root instanceof UnsupportedOperationException,
                "expected UnsupportedOperationException root cause, got " + root);
        Assertions.assertEquals("writeObject not implemented on native rand", root.getMessage());
    }
}
