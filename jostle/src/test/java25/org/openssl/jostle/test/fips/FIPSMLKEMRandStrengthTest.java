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
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.DrbgParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * JSLFIPS accepts a SecureRandom of every strength for every ML-KEM variant at key generation, at the KEM
 * KeyGenerator's encapsulate init and at the KTS cipher's wrap init, because the module draws its own entropy and
 * never reads the caller's source; each operation then succeeds. 3.1.2 has no ML-KEM at all.
 */
public class FIPSMLKEMRandStrengthTest
{
    private static final MLKEMParameterSpec[] SPECS = {
            MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024};
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Test
    public void everySourceStrengthIsAcceptedAndTheModuleEncapsulatesAndWraps() throws Exception
    {
        FipsModuleProfile profile = FipsModuleProfile.get();
        Provider fips = FIPSTestUtil.assumeFipsProvider();
        if (profile.isVersion312())
        {
            Assertions.assertNull(fips.getService("KeyPairGenerator", "ML-KEM-768"));
            return;
        }
        Assertions.assertEquals(FipsModuleProfile.MODULE_3_5_9, profile.version());
        for (MLKEMParameterSpec spec : SPECS)
        {
            for (int strength : new int[]{128, 192, 256})
            {
                SecureRandom rand = SecureRandom.getInstance("DRBG",
                        DrbgParameters.instantiation(strength, DrbgParameters.Capability.NONE, null));
                String what = spec.getName() + " with a " + strength + "-bit source";
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), fips);
                kpg.initialize(spec, rand);
                KeyPair kp = kpg.generateKeyPair();

                KeyGenerator sender = KeyGenerator.getInstance("ML-KEM", fips);
                sender.init(KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                        .withKeySizeInBits(256).build(), rand);
                SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
                KeyGenerator receiver = KeyGenerator.getInstance("ML-KEM", fips);
                receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate())
                        .withEncapsulatedKey(sent.getEncapsulation()).withAlgorithmName("AES")
                        .withKeySizeInBits(256).build());
                Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), what);

                byte[] raw = new byte[16];
                RANDOM.nextBytes(raw);
                SecretKeySpec key = new SecretKeySpec(raw, "AES");
                Cipher wrap = Cipher.getInstance("ML-KEM", fips);
                wrap.init(Cipher.WRAP_MODE, kp.getPublic(), new KTSParameterSpec.Builder("AES-KWP", 256).build(),
                        rand);
                byte[] wrapped = wrap.wrap(key);
                Cipher unwrap = Cipher.getInstance("ML-KEM", fips);
                unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), new KTSParameterSpec.Builder("AES-KWP", 256).build());
                Assertions.assertArrayEquals(raw, unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(),
                        what);
            }
        }
    }
}
