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

package org.openssl.jostle.test.mlkem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.rand.DefaultRandSource;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The caller's SecureRandom against the ML-KEM strength requirement, per variant, with BouncyCastle beside: the
 * KeyPairGenerator, the KEM KeyGenerator's encapsulate init and the KTS cipher's wrap init all refuse a source
 * reporting less strength than the variant needs, and use one reporting enough or none, ours included. Passing no
 * source draws from the provider's own DRBG. BouncyCastle accepts every source at all three.
 */
public class MLKEMRandStrengthAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final MLKEMParameterSpec[] SPECS = {
            MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024};
    // MLKEMParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
    private static final org.bouncycastle.jcajce.spec.MLKEMParameterSpec[] BC_SPECS = {
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_512,
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_768,
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_1024};
    private static final int[] STRENGTHS = {128, 192, 256};
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SecureRandom drbg(int strength) throws Exception
    {
        return SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(strength, DrbgParameters.Capability.NONE, null));
    }

    private static String refusal(int strength, MLKEMParameterSpec spec)
    {
        int required = spec.getRequiredStrengthBits();
        return "supplied SecureRandom reports " + strength + "-bit strength but " + spec.getName() + " requires "
                + required + "; pass a SecureRandom of at least " + required + " bits";
    }

    @Test
    public void theKeyPairGeneratorRefusesAWeakerSourceAndBouncyCastleAcceptsEverySource() throws Exception
    {
        for (int i = 0; i < SPECS.length; i++)
        {
            MLKEMParameterSpec spec = SPECS[i];
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
                    assertEncapsulates(jsl.generateKeyPair(), null);
                }

                KeyPairGenerator bc = KeyPairGenerator.getInstance(spec.getName(), BC);
                bc.initialize(BC_SPECS[i], rand);
                Assertions.assertNotNull(bc.generateKeyPair().getPrivate());
            }
            KeyPairGenerator jsl = KeyPairGenerator.getInstance(spec.getName(), JSL);
            jsl.initialize(spec, SecureRandom.getInstance("SHA1PRNG"));
            assertEncapsulates(jsl.generateKeyPair(), null);
        }
    }

    @Test
    public void encapsulateInitRefusesAWeakerSourceAndBouncyCastleAcceptsEverySource() throws Exception
    {
        for (int i = 0; i < SPECS.length; i++)
        {
            MLKEMParameterSpec spec = SPECS[i];
            KeyPair ours = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
            KeyPair theirs = KeyPairGenerator.getInstance(spec.getName(), BC).generateKeyPair();
            for (int strength : STRENGTHS)
            {
                SecureRandom rand = drbg(strength);
                if (strength < spec.getRequiredStrengthBits())
                {
                    KeyGenerator sender = KeyGenerator.getInstance("ML-KEM", JSL);
                    InvalidAlgorithmParameterException e = Assertions.assertThrows(
                            InvalidAlgorithmParameterException.class, () -> sender.init(generate(ours), rand));
                    Assertions.assertEquals(refusal(strength, spec), e.getMessage());
                }
                else
                {
                    assertEncapsulates(ours, rand);
                }

                KeyGenerator bc = KeyGenerator.getInstance("ML-KEM", BC);
                // KEMGenerateSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                bc.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(theirs.getPublic(), "AES", 256)
                        .build(), rand);
                Assertions.assertEquals(32, bc.generateKey().getEncoded().length, spec.getName());
            }
            assertEncapsulates(ours, SecureRandom.getInstance("SHA1PRNG"));
        }
    }

    @Test
    public void wrapInitRefusesAWeakerSourceAndBouncyCastleAcceptsEverySource() throws Exception
    {
        for (int i = 0; i < SPECS.length; i++)
        {
            MLKEMParameterSpec spec = SPECS[i];
            KeyPair ours = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
            KeyPair theirs = KeyPairGenerator.getInstance(spec.getName(), BC).generateKeyPair();
            for (int strength : STRENGTHS)
            {
                SecureRandom rand = drbg(strength);
                if (strength < spec.getRequiredStrengthBits())
                {
                    Cipher wrap = Cipher.getInstance("ML-KEM", JSL);
                    InvalidAlgorithmParameterException e = Assertions.assertThrows(
                            InvalidAlgorithmParameterException.class,
                            () -> wrap.init(Cipher.WRAP_MODE, ours.getPublic(), kts(), rand));
                    Assertions.assertEquals(refusal(strength, spec), e.getMessage());
                }
                else
                {
                    assertWraps(ours, rand);
                }

                Cipher bc = Cipher.getInstance("ML-KEM", BC);
                // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                bc.init(Cipher.WRAP_MODE, theirs.getPublic(),
                        new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AES-KWP", 256).build(), rand);
                byte[] raw = new byte[16];
                RANDOM.nextBytes(raw);
                Assertions.assertTrue(bc.wrap(new SecretKeySpec(raw, "AES")).length > 0, spec.getName());
            }
            assertWraps(ours, SecureRandom.getInstance("SHA1PRNG"));
        }
    }

    /**
     * Our own SecureRandom services report their DRBG strength, so they are judged as any other source: a strong
     * one is used, a weaker one refused with the same message.
     */
    @Test
    public void ourOwnSecureRandomIsJudgedByTheStrengthItReports() throws Exception
    {
        MLKEMParameterSpec spec = MLKEMParameterSpec.ml_kem_1024;
        KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
        SecureRandom strong = SecureRandom.getInstance("CTR-DRBG-AES256", JSL);
        Assertions.assertEquals(256, DefaultRandSource.strengthOf(strong));
        assertEncapsulates(kp, strong);
        assertWraps(kp, strong);

        SecureRandom weak = SecureRandom.getInstance("CTR-DRBG-AES128", JSL);
        int reported = DefaultRandSource.strengthOf(weak);
        Assertions.assertEquals(128, reported);
        KeyGenerator sender = KeyGenerator.getInstance("ML-KEM", JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> sender.init(generate(kp), weak));
        Assertions.assertEquals(refusal(reported, spec), e.getMessage());
    }

    private static KEMGenerateSpec generate(KeyPair kp)
    {
        return KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(256).build();
    }

    private static KTSParameterSpec kts()
    {
        return new KTSParameterSpec.Builder("AES-KWP", 256).build();
    }

    /** Encapsulates through our KEM KeyGenerator with {@code rand} (or none), and the other half opens it. */
    private static void assertEncapsulates(KeyPair kp, SecureRandom rand) throws Exception
    {
        KeyGenerator sender = KeyGenerator.getInstance("ML-KEM", JSL);
        KEMGenerateSpec spec = KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(256).build();
        if (rand == null)
        {
            sender.init(spec);
        }
        else
        {
            sender.init(spec, rand);
        }
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();
        KeyGenerator receiver = KeyGenerator.getInstance("ML-KEM", JSL);
        receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate())
                .withEncapsulatedKey(sent.getEncapsulation()).withAlgorithmName("AES").withKeySizeInBits(256).build());
        Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded());
    }

    /** Wraps through our KTS cipher with {@code rand}, and unwraps to the same key. */
    private static void assertWraps(KeyPair kp, SecureRandom rand) throws Exception
    {
        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        SecretKeySpec key = new SecretKeySpec(raw, "AES");
        Cipher wrap = Cipher.getInstance("ML-KEM", JSL);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), new KTSParameterSpec.Builder("AES-KWP", 256).build(), rand);
        byte[] wrapped = wrap.wrap(key);
        Cipher unwrap = Cipher.getInstance("ML-KEM", JSL);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), new KTSParameterSpec.Builder("AES-KWP", 256).build());
        Assertions.assertArrayEquals(key.getEncoded(),
                unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded());
    }
}
