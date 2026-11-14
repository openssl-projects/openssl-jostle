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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.test.dh.KeyAgreementCalls;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.interfaces.DHPublicKey;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The JSLFIPS half of ForeignKeyTranslationAgreementTest: a BouncyCastle 1.87 key given to a JSLFIPS entry point is
 * translated by its encoding into the module; a key with no encoding is refused naming its class. ML-KEM cells run
 * only where the loaded module implements ML-KEM.
 */
public class FIPSForeignKeyTranslationAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static void assumeMlKem()
    {
        Assumptions.assumeTrue(Security.getProvider(FIPS).getService("KeyGenerator", "ML-KEM-768") != null,
                "the loaded FIPS module implements no ML-KEM");
    }

    private static KEMGenerateSpec generateSpec(PublicKey key)
    {
        return KEMGenerateSpec.builder().withPublicKey(key).withAlgorithmName("AES").withKeySizeInBits(256).build();
    }

    /** JSLFIPS encapsulates to a BouncyCastle public key; BouncyCastle decapsulates the same secret. */
    @Test
    public void mlkemKeyGenerator_encapsulatesToABouncyCastlePublicKey() throws Exception
    {
        assumeMlKem();
        KeyPair bc = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        KeyGenerator fips = KeyGenerator.getInstance("ML-KEM-768", FIPS);
        fips.init(generateSpec(bc.getPublic()));
        SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) fips.generateKey();

        KeyGenerator ref = KeyGenerator.getInstance("ML-KEM", BC);
        // KEMExtractSpec: BouncyCastle's is qualified, jostle's is imported
        ref.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec(bc.getPrivate(), sent.getEncapsulation(), "AES", 256));
        Assertions.assertArrayEquals(ref.generateKey().getEncoded(), sent.getEncoded());
    }

    /** BouncyCastle encapsulates; JSLFIPS decapsulates with BouncyCastle's private key. */
    @Test
    public void mlkemKeyGenerator_decapsulatesWithABouncyCastlePrivateKey() throws Exception
    {
        assumeMlKem();
        KeyPair bc = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        KeyGenerator ref = KeyGenerator.getInstance("ML-KEM", BC);
        // KEMGenerateSpec and SecretKeyWithEncapsulation: BouncyCastle's are qualified, jostle's are imported
        ref.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(bc.getPublic(), "AES", 256));
        org.bouncycastle.jcajce.SecretKeyWithEncapsulation sent =
                (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) ref.generateKey();

        KeyGenerator fips = KeyGenerator.getInstance("ML-KEM-768", FIPS);
        fips.init(new KEMExtractSpec(bc.getPrivate(), "AES", 256, sent.getEncapsulation()));
        Assertions.assertArrayEquals(sent.getEncoded(), fips.generateKey().getEncoded());
    }

    /** A key with no encoding is refused with InvalidAlgorithmParameterException naming its class. */
    @Test
    public void mlkemKeyGenerator_refusesAKeyWithNoEncoding() throws Exception
    {
        assumeMlKem();
        PublicKey none = new PublicKey()
        {
            @Override
            public String getAlgorithm()
            {
                return "ML-KEM";
            }

            @Override
            public String getFormat()
            {
                return null;
            }

            @Override
            public byte[] getEncoded()
            {
                return null;
            }
        };
        KeyGenerator fips = KeyGenerator.getInstance("ML-KEM-768", FIPS);
        InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                () -> fips.init(generateSpec(none)));
        Assertions.assertTrue(e.getMessage().contains(none.getClass().getName()), e.getMessage());
    }

    /** ECDH and DH on JSLFIPS agree with BouncyCastle when given BouncyCastle's keys. */
    @Test
    public void keyAgreements_agreeWithBouncyCastleOnBouncyCastleKeys() throws Exception
    {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", BC);
        ecGen.initialize(new ECGenParameterSpec("P-256"));
        KeyPair ecA = ecGen.generateKeyPair();
        KeyPair ecB = ecGen.generateKeyPair();

        KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH", BC);
        dhGen.initialize(2048);
        KeyPair dhA = dhGen.generateKeyPair();
        KeyPairGenerator dhPeerGen = KeyPairGenerator.getInstance("DH", BC);
        dhPeerGen.initialize(((DHPublicKey) dhA.getPublic()).getParams());
        KeyPair dhB = dhPeerGen.generateKeyPair();

        Object[][] cases = {{"ECDH", ecA, ecB}, {"DH", dhA, dhB}};
        for (Object[] c : cases)
        {
            String agreement = (String) c[0];
            KeyPair a = (KeyPair) c[1];
            KeyPair b = (KeyPair) c[2];
            KeyAgreement fips = KeyAgreement.getInstance(agreement, FIPS);
            fips.init(a.getPrivate());
            KeyAgreementCalls.phase(fips, b.getPublic());
            KeyAgreement ref = KeyAgreement.getInstance(agreement, BC);
            ref.init(b.getPrivate());
            KeyAgreementCalls.phase(ref, a.getPublic());
            Assertions.assertArrayEquals(KeyAgreementCalls.secret(ref), KeyAgreementCalls.secret(fips), agreement);
        }
    }

    /** The field the ML-KEM generator keeps its accepted key in; a translated key is read from it. */
    private static final String KEPT_KEY_FIELD = "kemKey";

    /** Runs the provider's own FIPS generator init on spec and returns the key it kept. */
    private static OSSLKey keptKey(Provider provider, AlgorithmParameterSpec spec) throws Exception
    {
        Object spi = provider.getService("KeyGenerator", "ML-KEM-768").newInstance(null);
        Method init = spi.getClass().getDeclaredMethod("engineInit", AlgorithmParameterSpec.class, SecureRandom.class);
        init.setAccessible(true);
        init.invoke(spi, spec, null);
        Field kept;
        try
        {
            kept = spi.getClass().getDeclaredField(KEPT_KEY_FIELD);
        }
        catch (NoSuchFieldException e)
        {
            throw new AssertionError("the generator no longer keeps its key in " + KEPT_KEY_FIELD, e);
        }
        kept.setAccessible(true);
        OSSLKey key = (OSSLKey) kept.get(spi);
        Assertions.assertNotNull(key, KEPT_KEY_FIELD + " is not set after init");
        return key;
    }

    /**
     * The library binding of a translated key: a BouncyCastle key handed to the JSLFIPS ML-KEM generator is kept
     * bound to the FIPS interface library and owned by its "fips" OpenSSL provider, in both halves.
     */
    @Test
    public void translatedMlkemKey_libraryBindingIsTheFipsLibrary() throws Exception
    {
        assumeMlKem();
        KeyPair bc = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        AlgorithmParameterSpec[] specs = {
            KEMGenerateSpec.builder().withPublicKey(bc.getPublic()).withAlgorithmName("AES").withKeySizeInBits(256)
                    .build(),
            new KEMExtractSpec(bc.getPrivate(), "AES", 256, new byte[1088])};
        for (AlgorithmParameterSpec spec : specs)
        {
            OSSLKey key = keptKey(Security.getProvider(FIPS), spec);
            PKEYKeySpec keySpec = key.getSpec();
            String label = spec.getClass().getSimpleName();
            Assertions.assertEquals(true, keySpec.getSpecNI().getClass().getSimpleName().contains("FIPS"),
                    label + ": " + keySpec.getSpecNI().getClass().getName());
            Assertions.assertEquals("fips", keySpec.getSpecNI().getKeyProvider(keySpec.getReference()), label);
            Assertions.assertNotNull(key.getSpec(), label);
        }
    }

}
