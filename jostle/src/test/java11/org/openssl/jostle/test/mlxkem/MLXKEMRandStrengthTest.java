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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.rand.DefaultRandSource;

import javax.crypto.KeyGenerator;
import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The caller's SecureRandom against each hybrid group's strength requirement, with HybridRef beside: the
 * KeyPairGenerator and the KEM KeyGenerator's encapsulate init refuse a source reporting less strength than the group
 * needs, and use one reporting enough or none, ours included. Passing no source draws from the provider's own DRBG.
 * HybridRef generates and encapsulates with every source. No BouncyCastle JCE name serves these groups.
 */
public class MLXKEMRandStrengthTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final int[] STRENGTHS = {128, 192, 256};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecureRandom drbg(int strength) throws Exception
    {
        return SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(strength, DrbgParameters.Capability.NONE, null));
    }

    private static String refusal(int strength, MLXKEMParameterSpec spec)
    {
        int required = spec.getRequiredStrengthBits();
        return "supplied SecureRandom reports " + strength + "-bit strength but " + spec.getName() + " requires "
                + required + "; pass a SecureRandom of at least " + required + " bits";
    }

    /** With no source anywhere, every group generates and encapsulates from the provider's own DRBG. */
    @Test
    public void noSourceGeneratesAndEncapsulatesForEveryGroup() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            assertEncapsulates(spec, KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair(), null);
        }
    }

    @Test
    public void theKeyPairGeneratorRefusesAWeakerSource() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            int required = spec.getRequiredStrengthBits();
            for (int strength : STRENGTHS)
            {
                SecureRandom rand = drbg(strength);
                KeyPairGenerator jsl = KeyPairGenerator.getInstance(spec.getName(), JSL);
                if (strength < required)
                {
                    InvalidAlgorithmParameterException e = Assertions.assertThrows(
                            InvalidAlgorithmParameterException.class, () -> jsl.initialize(spec, rand));
                    Assertions.assertEquals("supplied SecureRandom reports " + strength + "-bit strength but "
                            + spec.getName() + " requires " + required, e.getMessage());
                }
                else
                {
                    jsl.initialize(spec, rand);
                    assertEncapsulates(spec, jsl.generateKeyPair(), null);
                }
                Assertions.assertTrue(HybridRef.Party.generate(spec, rand).share.length > 0, spec.getName());
            }
        }
    }

    /** 128 bits is refused for every group, 192 for the two 1024 groups; SHA1PRNG reports none and is used. */
    @Test
    public void encapsulateInitRefusesAWeakerSource() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair ours = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
            byte[] share = ((MLXKEMPublicKey) ours.getPublic()).getPublicData();
            for (int strength : STRENGTHS)
            {
                SecureRandom rand = drbg(strength);
                if (strength < spec.getRequiredStrengthBits())
                {
                    KeyGenerator sender = KeyGenerator.getInstance(spec.getName(), JSL);
                    InvalidAlgorithmParameterException e = Assertions.assertThrows(
                            InvalidAlgorithmParameterException.class, () -> sender.init(generate(spec, ours), rand));
                    Assertions.assertEquals(refusal(strength, spec), e.getMessage());
                }
                else
                {
                    assertEncapsulates(spec, ours, rand);
                }
                Assertions.assertEquals(2, HybridRef.encapsulate(spec, share, rand).length, spec.getName());
            }
            assertEncapsulates(spec, ours, SecureRandom.getInstance("SHA1PRNG"));
        }
    }

    /** Our own SecureRandom services report their DRBG strength and are judged like any other source. */
    @Test
    public void ourOwnSecureRandomIsJudgedByTheStrengthItReports() throws Exception
    {
        MLXKEMParameterSpec spec = MLXKEMParameterSpec.x448_mlkem1024;
        KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
        SecureRandom strong = SecureRandom.getInstance("CTR-DRBG-AES256", JSL);
        Assertions.assertEquals(256, DefaultRandSource.strengthOf(strong));
        assertEncapsulates(spec, kp, strong);

        SecureRandom weak = SecureRandom.getInstance("CTR-DRBG-AES128", JSL);
        int reported = DefaultRandSource.strengthOf(weak);
        Assertions.assertEquals(128, reported);
        KeyGenerator sender = KeyGenerator.getInstance(spec.getName(), JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> sender.init(generate(spec, kp), weak));
        Assertions.assertEquals(refusal(reported, spec), e.getMessage());
    }

    private static KEMGenerateSpec generate(MLXKEMParameterSpec spec, KeyPair kp)
    {
        return KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8).build();
    }

    /** Encapsulates through our KeyGenerator with {@code rand} (or none), and the other half opens it. */
    private static void assertEncapsulates(MLXKEMParameterSpec spec, KeyPair kp, SecureRandom rand) throws Exception
    {
        KeyGenerator sender = KeyGenerator.getInstance(spec.getName(), JSL);
        if (rand == null)
        {
            sender.init(generate(spec, kp));
        }
        else
        {
            sender.init(generate(spec, kp), rand);
        }
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
        KeyGenerator receiver = KeyGenerator.getInstance(spec.getName(), JSL);
        receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate())
                .withEncapsulatedKey(sent.getEncapsulation()).withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8).build());
        Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), spec.getName());
    }
}
