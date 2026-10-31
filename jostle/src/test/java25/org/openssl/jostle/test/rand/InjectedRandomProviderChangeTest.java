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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kts.InjectedRandom;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * The JDK replaces the SecureRandom it injects into an init whenever the provider list changes. An init with no
 * SecureRandom must still be recognised as such afterwards, and draw from the provider's own DRBG; otherwise a JDK
 * default weaker than the parameter set (the SUN DRBG at 128 bits, made the default here) is refused as though the
 * caller had supplied it. The registry is restored after each cell.
 */
public class InjectedRandomProviderChangeTest
{
    private static final String DRBG_FIRST = "DRBGFirst";
    private static final int JDK_DRBG_BITS = 128;
    private static final int REQUIRED_BITS = 256;
    private static final int WRAPPED_KEY_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Provider[] original;
    private Provider jsl;

    @BeforeEach
    public void snapshotTheRegistry()
    {
        original = Security.getProviders();
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
        }
    }

    /** Restores the registry and asserts it by name and position, so a partial restore is red here. */
    @AfterEach
    public void restoreTheRegistry()
    {
        if (original == null)
        {
            return;
        }
        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        for (int i = 0; i < original.length; i++)
        {
            Security.insertProviderAt(original[i], i + 1);
        }
        Provider[] restored = Security.getProviders();
        Assertions.assertEquals(original.length, restored.length, "provider count not restored");
        for (int i = 0; i < original.length; i++)
        {
            Assertions.assertEquals(original[i].getName(), restored[i].getName(),
                    "provider at position " + i + " not restored");
        }
    }

    /** A one-service provider ahead of the rest makes the SUN DRBG, at its 128-bit default, the JDK default. */
    private static void makeTheWeakDrbgTheDefault()
    {
        Provider first = new Provider(DRBG_FIRST, "1", "the SUN DRBG ahead of the rest")
        {
        };
        first.put("SecureRandom.DRBG", "sun.security.provider.DRBG");
        Assertions.assertEquals(1, Security.insertProviderAt(first, 1));
        SecureRandom def = new SecureRandom();
        Assertions.assertEquals("DRBG", def.getAlgorithm());
        Assertions.assertEquals(JDK_DRBG_BITS, ((DrbgParameters.Instantiation) def.getParameters()).getStrength());
    }

    private static KEMGenerateSpec generate(KeyPair kp, int keyBits)
    {
        return KEMGenerateSpec.builder().withPublicKey(kp.getPublic()).withAlgorithmName("AES")
                .withKeySizeInBits(keyBits).build();
    }

    /** Init with no SecureRandom is recognised, and the encapsulation it makes opens. */
    private void initWithNoRandomIsRecognised(String generator, KeyPair kp, int keyBits, String label)
        throws Exception
    {
        KeyGenerator sender = KeyGenerator.getInstance(generator, jsl);
        sender.init(generate(kp, keyBits));
        Assertions.assertTrue(InjectedRandom.lastInitSawInjectedDefault(), label);
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();

        KeyGenerator receiver = KeyGenerator.getInstance(generator, jsl);
        receiver.init(KEMExtractSpec.builder().withPrivate(kp.getPrivate()).withAlgorithmName("AES")
                .withKeySizeInBits(keyBits).withEncapsulatedKey(sent.getEncapsulation()).build());
        Assertions.assertArrayEquals(sent.getEncoded(), receiver.generateKey().getEncoded(), label);
    }

    private void survivesProviderChanges(String generator, KeyPair kp, int keyBits) throws Exception
    {
        initWithNoRandomIsRecognised(generator, kp, keyBits, generator + ": before any change");

        makeTheWeakDrbgTheDefault();
        initWithNoRandomIsRecognised(generator, kp, keyBits, generator + ": after an insert");

        Security.removeProvider(DRBG_FIRST);
        initWithNoRandomIsRecognised(generator, kp, keyBits, generator + ": after a remove");

        // Control: the same 128-bit DRBG passed by the caller is still refused.
        makeTheWeakDrbgTheDefault();
        SecureRandom weak = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(JDK_DRBG_BITS, DrbgParameters.Capability.RESEED_ONLY, null));
        KeyGenerator explicit = KeyGenerator.getInstance(generator, jsl);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> explicit.init(generate(kp, keyBits), weak));
        Assertions.assertEquals("supplied SecureRandom reports " + JDK_DRBG_BITS + "-bit strength but " + generator
                + " requires " + REQUIRED_BITS + "; pass a SecureRandom of at least " + REQUIRED_BITS + " bits",
                e.getMessage());
    }

    /** A KTS wrap init with no SecureRandom is recognised, and the key it wraps unwraps. */
    private void wrapInitWithNoRandomIsRecognised(KeyPair kp, String label) throws Exception
    {
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES-KWP", REQUIRED_BITS).build();
        Cipher wrap = Cipher.getInstance("ML-KEM", jsl);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
        Assertions.assertTrue(InjectedRandom.lastInitSawInjectedDefault(), label);
        byte[] raw = new byte[WRAPPED_KEY_BYTES];
        RANDOM.nextBytes(raw);
        byte[] wrapped = wrap.wrap(new SecretKeySpec(raw, "AES"));

        Cipher unwrap = Cipher.getInstance("ML-KEM", jsl);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Assertions.assertArrayEquals(raw, unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(), label);
    }

    @Test
    public void ktsWrapInitWithNoRandomSurvivesProviderChanges() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-1024", jsl).generateKeyPair();
        wrapInitWithNoRandomIsRecognised(kp, "KTS wrap: before any change");

        makeTheWeakDrbgTheDefault();
        wrapInitWithNoRandomIsRecognised(kp, "KTS wrap: after an insert");

        Security.removeProvider(DRBG_FIRST);
        wrapInitWithNoRandomIsRecognised(kp, "KTS wrap: after a remove");
    }

    @Test
    public void mlKemInitWithNoRandomSurvivesProviderChanges() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-1024", jsl).generateKeyPair();
        survivesProviderChanges("ML-KEM-1024", kp, REQUIRED_BITS);
    }

    @Test
    public void hybridInitWithNoRandomSurvivesProviderChanges() throws Exception
    {
        MLXKEMParameterSpec spec = MLXKEMParameterSpec.secp384r1_mlkem1024;
        Assertions.assertEquals(REQUIRED_BITS, spec.getRequiredStrengthBits());
        KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), jsl).generateKeyPair();
        survivesProviderChanges(spec.getName(), kp, spec.getSharedSecretBytes() * 8);
    }
}
