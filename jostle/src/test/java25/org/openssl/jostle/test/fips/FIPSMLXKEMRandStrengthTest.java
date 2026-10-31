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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.KeyGenerator;
import java.security.DrbgParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Set;

/**
 * JSLFIPS accepts a SecureRandom of every strength for every hybrid group it serves, at key generation and at the
 * KEM KeyGenerator's encapsulate init, because the module draws its own entropy and never reads the caller's source;
 * each operation then succeeds. 3.1.2 serves no hybrid group.
 */
public class FIPSMLXKEMRandStrengthTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Test
    public void everySourceStrengthIsAcceptedAndTheModuleEncapsulates() throws Exception
    {
        Set<String> served = FipsModuleProfile.get().hybridKemGroups();
        Provider fips = FIPSTestUtil.assumeFipsProvider();
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            String name = spec.getName();
            Assertions.assertEquals(served.contains(name), fips.getService("KeyPairGenerator", name) != null, name);
            if (!served.contains(name))
            {
                continue;
            }
            for (int strength : new int[]{128, 192, 256})
            {
                SecureRandom rand = SecureRandom.getInstance("DRBG",
                        DrbgParameters.instantiation(strength, DrbgParameters.Capability.NONE, null));
                String what = name + " with a " + strength + "-bit source";
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, fips);
                kpg.initialize(spec, rand);
                KeyPair kp = kpg.generateKeyPair();

                KeyGenerator sender = KeyGenerator.getInstance(name, fips);
                sender.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                        .withKeySizeInBits(spec.getSharedSecretBytes() * 8).build(), rand);
                SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
                KeyGenerator receiver = KeyGenerator.getInstance(name, fips);
                receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate())
                        .withEncapsulatedKey(sent.getEncapsulation()).withAlgorithmName("AES")
                        .withKeySizeInBits(spec.getSharedSecretBytes() * 8).build());
                Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), what);
            }
        }
    }
}
