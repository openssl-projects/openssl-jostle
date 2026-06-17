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

package org.openssl.jostle.test.rand;

import java.security.SecureRandom;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.Provider;
import java.security.Security;

public class RandServiceTest
{
    private static final int NATIVE_REQUEST_BOUNDARY = 65536;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void getInstanceDRBG() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[32];
        random.nextBytes(output);

        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, random.getProvider().getName());
        Assertions.assertEquals("DRBG", random.getAlgorithm());
        Assertions.assertFalse(Arrays.areEqual(new byte[32], output));
    }

    @Test
    public void defaultAliasIsRegistered() throws Exception
    {
        Provider provider = Security.getProvider(JostleProvider.PROVIDER_NAME);
        SecureRandom random = SecureRandom.getInstance("DEFAULT", JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[32];

        random.nextBytes(output);

        Assertions.assertNotNull(provider.getService("SecureRandom", "DRBG"));
        Assertions.assertNotNull(provider.getService("SecureRandom", "DEFAULT"));
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, random.getProvider().getName());
        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
        Assertions.assertNull(provider.getService("SecureRandom", "NativePRNG"));
        Assertions.assertNull(provider.getService("SecureRandom", "NativePRNGNonBlocking"));
        Assertions.assertNull(provider.getService("SecureRandom", "SHA1PRNG"));
        Assertions.assertNull(provider.getService("SecureRandom", "DefaultRandom"));
    }

    @Test
    public void drbgThreadSafeAttribute()
    {
        Provider provider = Security.getProvider(JostleProvider.PROVIDER_NAME);

        Assertions.assertEquals("true", provider.get("SecureRandom.DRBG ThreadSafe"));
    }

    @Test
    public void generateSeed() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] seed = random.generateSeed(14);

        Assertions.assertEquals(14, seed.length);
    }

    @Test
    public void generateSeedNegative() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () -> random.generateSeed(-1));
    }

    @Test
    public void nextBytesNull() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(NullPointerException.class, () -> random.nextBytes(null));
    }

    @Test
    public void nextBytesAcceptsLargeRequest() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[NATIVE_REQUEST_BOUNDARY + 17];

        random.nextBytes(output);

        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
    }

    @Test
    public void setSeedIsAccepted() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        random.setSeed(23L);
        random.setSeed("seed".getBytes("UTF-8"));
    }

    @Test
    public void nextBytesProducesDifferentOutputAcrossCalls() throws Exception
    {
        // Two draws from one instance must differ: a stub returning a fixed
        // (non-zero) constant passes the all-zero checks above but fails here.
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] first = new byte[32];
        byte[] second = new byte[32];

        random.nextBytes(first);
        random.nextBytes(second);

        Assertions.assertFalse(Arrays.areEqual(first, second));
    }

    @Test
    public void independentInstancesProduceDifferentStreams() throws Exception
    {
        // Two independent DRBG instances are each seeded from the OS-seeded
        // parent, so their first draws must differ.
        SecureRandom first = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        SecureRandom second = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] firstOutput = new byte[32];
        byte[] secondOutput = new byte[32];

        first.nextBytes(firstOutput);
        second.nextBytes(secondOutput);

        Assertions.assertFalse(Arrays.areEqual(firstOutput, secondOutput));
    }

    @Test
    public void serializationIsNotSupported() throws Exception
    {
        // A native-backed DRBG instance holds an EVP_RAND_CTX handle that cannot
        // be persisted, so serialization is deliberately forbidden: writeObject
        // throws and SecureRandom serialization fails deterministically.
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
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
