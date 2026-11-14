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

package org.openssl.jostle.test.provider;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.test.dh.KeyAgreementCalls;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A key object from another provider, given to a JSL entry point that takes a key, is translated by its encoding as
 * JSL's own KeyFactory translates it; a key with no encoding, or of the wrong algorithm, is refused with the entry
 * point's typed exception and a message naming the key's class. BouncyCastle 1.87 makes the foreign keys and is the
 * reference for the result and for the refusal type.
 *
 * <p>The ML-KEM KTS cipher and the EC and XDH agreements with the JDK's foreign keys are in
 * ForeignKeyKemEcXdhAgreementTest; a key from another Jostle provider instance stays refused, since only its
 * encoding crosses.
 */
public class ForeignKeyTranslationAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String[] MLKEM_SETS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** A key with no encoding, as a hardware token or a wrapper object would present one. */
    private static final class NoEncodingPublicKey implements PublicKey
    {
        private final String algorithm;

        NoEncodingPublicKey(String algorithm)
        {
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm()
        {
            return algorithm;
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
    }

    /** The private-key counterpart of {@link NoEncodingPublicKey}. */
    private static final class NoEncodingPrivateKey implements PrivateKey
    {
        private final String algorithm;

        NoEncodingPrivateKey(String algorithm)
        {
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm()
        {
            return algorithm;
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
    }

    private static KeyPair bcPair(String algorithm, AlgorithmParameterSpec spec) throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm, BC);
        if (spec != null)
        {
            g.initialize(spec);
        }
        return g.generateKeyPair();
    }

    private static KEMGenerateSpec generateSpec(PublicKey key)
    {
        return KEMGenerateSpec.builder().withPublicKey(key).withAlgorithmName("AES").withKeySizeInBits(256).build();
    }

    private static void assertNamesTheClass(Exception e, Key key)
    {
        Assertions.assertTrue(e.getMessage().contains(key.getClass().getName()),
                "the refusal must name the key's class, got: " + e.getMessage());
    }

    /** JSL encapsulates to a BouncyCastle public key; BouncyCastle decapsulates the same secret. */
    @Test
    public void mlkemKeyGenerator_encapsulatesToABouncyCastlePublicKey() throws Exception
    {
        for (String set : MLKEM_SETS)
        {
            KeyPair bc = bcPair(set, null);
            for (String generator : new String[]{set, "ML-KEM"})
            {
                KeyGenerator jsl = KeyGenerator.getInstance(generator, JSL);
                jsl.init(generateSpec(bc.getPublic()));
                SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) jsl.generateKey();

                KeyGenerator ref = KeyGenerator.getInstance("ML-KEM", BC);
                // KEMExtractSpec: BouncyCastle's is qualified, jostle's is imported
                ref.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec(bc.getPrivate(), sent.getEncapsulation(),
                        "AES", 256));
                Assertions.assertArrayEquals(ref.generateKey().getEncoded(), sent.getEncoded(),
                        generator + " to a BouncyCastle " + set + " key");
            }
        }
    }

    /** BouncyCastle encapsulates; JSL decapsulates with BouncyCastle's private key and derives the same secret. */
    @Test
    public void mlkemKeyGenerator_decapsulatesWithABouncyCastlePrivateKey() throws Exception
    {
        for (String set : MLKEM_SETS)
        {
            KeyPair bc = bcPair(set, null);
            KeyGenerator ref = KeyGenerator.getInstance("ML-KEM", BC);
            // KEMGenerateSpec and SecretKeyWithEncapsulation: BouncyCastle's are qualified, jostle's are imported
            ref.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(bc.getPublic(), "AES", 256));
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation sent =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) ref.generateKey();

            for (String generator : new String[]{set, "ML-KEM"})
            {
                KeyGenerator jsl = KeyGenerator.getInstance(generator, JSL);
                jsl.init(new KEMExtractSpec(bc.getPrivate(), "AES", 256, sent.getEncapsulation()));
                SecretKey received = jsl.generateKey();
                Assertions.assertArrayEquals(sent.getEncoded(), received.getEncoded(),
                        generator + " with a BouncyCastle " + set + " private key");
            }
        }
    }

    /**
     * A key with no encoding, or of the wrong algorithm, is refused with InvalidAlgorithmParameterException naming
     * its class, in both halves; BouncyCastle refuses the same keys with the same type, measured live.
     */
    @Test
    public void mlkemKeyGenerator_refusesAKeyItCannotTranslate() throws Exception
    {
        KeyPair ec = bcPair("EC", new ECGenParameterSpec("P-256"));
        Key[] publics = {new NoEncodingPublicKey("ML-KEM"), ec.getPublic()};
        Key[] privates = {new NoEncodingPrivateKey("ML-KEM"), ec.getPrivate()};
        for (Key key : publics)
        {
            KeyGenerator jsl = KeyGenerator.getInstance("ML-KEM-768", JSL);
            InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> jsl.init(generateSpec((PublicKey) key)));
            assertNamesTheClass(e, key);

            KeyGenerator ref = KeyGenerator.getInstance("ML-KEM", BC);
            // KEMGenerateSpec: BouncyCastle's is qualified, jostle's is imported
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> ref.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec((PublicKey) key, "AES", 256)));
        }
        for (Key key : privates)
        {
            KeyGenerator jsl = KeyGenerator.getInstance("ML-KEM-768", JSL);
            InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> jsl.init(new KEMExtractSpec((PrivateKey) key, "AES", 256, new byte[1088])));
            assertNamesTheClass(e, key);

            KeyGenerator ref = KeyGenerator.getInstance("ML-KEM", BC);
            // KEMExtractSpec: BouncyCastle's is qualified, jostle's is imported
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> ref.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec((PrivateKey) key, new byte[1088],
                            "AES", 256)));
        }
    }

    /** A translated key of another parameter set meets the same check a JSL key of that set meets. */
    @Test
    public void mlkemKeyGenerator_refusesATranslatedKeyOfAnotherParameterSet() throws Exception
    {
        KeyPair bc512 = bcPair("ML-KEM-512", null);
        KeyGenerator jsl = KeyGenerator.getInstance("ML-KEM-768", JSL);
        InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                () -> jsl.init(generateSpec(bc512.getPublic())));
        Assertions.assertEquals("expected ML-KEM-768 but got ML-KEM-512", e.getMessage());
    }

    /** Translation is for keys of other providers: a key from another Jostle provider instance stays refused. */
    @Test
    public void mlkemKeyGenerator_stillRefusesAKeyFromAnotherJostleInstance() throws Exception
    {
        Provider other = new JostleProvider();
        KeyPair otherPair = KeyPairGenerator.getInstance("ML-KEM-768", other).generateKeyPair();
        KeyGenerator jsl = KeyGenerator.getInstance("ML-KEM-768", JSL);
        InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                () -> jsl.init(generateSpec(otherPair.getPublic())));
        Assertions.assertTrue(e.getMessage().startsWith("public key was created by a different Jostle provider"),
                e.getMessage());
    }

    /** A hybrid KEM key has no encoding, so no foreign key translates; the refusal names the key's class. */
    @Test
    public void mlxkemKeyGenerator_refusesAForeignKeyNamingItsClass() throws Exception
    {
        String name = null;
        for (Provider.Service s : Security.getProvider(JSL).getServices())
        {
            if ("KeyGenerator".equals(s.getType()) && s.getAlgorithm().toUpperCase().contains("MLKEM")
                    && !s.getAlgorithm().startsWith("ML-KEM") && !s.getAlgorithm().equals("MLKEM"))
            {
                name = s.getAlgorithm();
                break;
            }
        }
        Assertions.assertNotNull(name, "JSL must serve a hybrid KEM KeyGenerator");
        KeyPair x25519 = bcPair("X25519", null);
        for (Key key : new Key[]{x25519.getPublic(), new NoEncodingPublicKey(name)})
        {
            KeyGenerator jsl = KeyGenerator.getInstance(name, JSL);
            InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> jsl.init(generateSpec((PublicKey) key)));
            Assertions.assertEquals("Only MLXKEMPublicKey is supported, not " + key.getClass().getName(),
                    e.getMessage());
        }
    }

    /**
     * Each key agreement JSL serves agrees with BouncyCastle when given BouncyCastle's keys at init and at the last
     * phase.
     */
    @Test
    public void keyAgreements_agreeWithBouncyCastleOnBouncyCastleKeys() throws Exception
    {
        Object[][] cases = {
            {"ECDH", "EC", new ECGenParameterSpec("P-256")},
            {"X25519", "X25519", null},
            {"X448", "X448", null},
            {"DH", "DH", null}};
        for (Object[] c : cases)
        {
            String agreement = (String) c[0];
            KeyPair a = bcPair((String) c[1], (AlgorithmParameterSpec) c[2]);
            KeyPair b;
            if ("DH".equals(agreement))
            {
                KeyPairGenerator g = KeyPairGenerator.getInstance("DH", BC);
                g.initialize(((DHPublicKey) a.getPublic()).getParams());
                b = g.generateKeyPair();
            }
            else
            {
                b = bcPair((String) c[1], (AlgorithmParameterSpec) c[2]);
            }

            KeyAgreement jsl = KeyAgreement.getInstance(agreement, JSL);
            jsl.init(a.getPrivate());
            KeyAgreementCalls.phase(jsl, b.getPublic());
            KeyAgreement ref = KeyAgreement.getInstance(agreement, BC);
            ref.init(b.getPrivate());
            KeyAgreementCalls.phase(ref, a.getPublic());
            Assertions.assertArrayEquals(KeyAgreementCalls.secret(ref), KeyAgreementCalls.secret(jsl), agreement);
        }
    }

    /**
     * Every other entry that takes a key refuses a key with no encoding with InvalidKeyException naming its class:
     * the ML-KEM and RSA KTS ciphers, the ETSI KEM, and each key agreement at init and at the last phase.
     */
    @Test
    public void everyKeyTakingEntryRefusesAKeyWithNoEncodingNamingItsClass() throws Exception
    {
        KTSParameterSpec kts = new KTSParameterSpec.Builder("AES", 256, new byte[8])
                .withKdfAlgorithm(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)).getEncoded())
                .build();
        Object[][] ciphers = {
            {"ML-KEM", kts, "ML-KEM"},
            {"RSA-KTS-KEM-KWS", kts, "RSA"},
            {"ETSIKEMwithSHA256", new IESKEMParameterSpec(new byte[8]), "EC"}};
        int checked = 0;
        for (Object[] c : ciphers)
        {
            for (int mode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
            {
                Key key = mode == Cipher.WRAP_MODE ? new NoEncodingPublicKey((String) c[2])
                        : new NoEncodingPrivateKey((String) c[2]);
                Cipher cipher = Cipher.getInstance((String) c[0], JSL);
                InvalidKeyException e = assertThrows(InvalidKeyException.class,
                        () -> cipher.init(mode, key, (AlgorithmParameterSpec) c[1]), c[0] + " mode " + mode);
                assertNamesTheClass(e, key);
                checked++;
            }
        }

        Object[][] agreements = {
            {"ECDH", "EC", new ECGenParameterSpec("P-256")},
            {"X25519", "X25519", null},
            {"DH", "DH", null}};
        for (Object[] a : agreements)
        {
            String agreement = (String) a[0];
            KeyPairGenerator g = KeyPairGenerator.getInstance((String) a[1], JSL);
            if (a[2] != null)
            {
                g.initialize((AlgorithmParameterSpec) a[2]);
            }
            KeyPair own = g.generateKeyPair();

            Key noPrivate = new NoEncodingPrivateKey((String) a[1]);
            KeyAgreement atInit = KeyAgreement.getInstance(agreement, JSL);
            assertNamesTheClass(assertThrows(InvalidKeyException.class, () -> atInit.init(noPrivate), agreement),
                    noPrivate);

            Key noPublic = new NoEncodingPublicKey((String) a[1]);
            KeyAgreement atPhase = KeyAgreement.getInstance(agreement, JSL);
            atPhase.init(own.getPrivate());
            assertNamesTheClass(assertThrows(InvalidKeyException.class,
                    () -> KeyAgreementCalls.phase(atPhase, noPublic), agreement), noPublic);
            checked += 2;
        }
        Assertions.assertEquals(12, checked, "every entry must be driven");
    }

    /** The field the ML-KEM generator keeps its accepted key in; a translated key is read from it. */
    private static final String KEPT_KEY_FIELD = "kemKey";

    /** Runs the provider's own base generator init on spec and returns the key it kept. */
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
     * The library binding of a translated key: a BouncyCastle key handed to the JSL ML-KEM generator is kept
     * bound to the base interface library and owned by its "default" OpenSSL provider, in both halves.
     */
    @Test
    public void translatedMlkemKey_libraryBindingIsTheBaseLibrary() throws Exception
    {
        KeyPair bc = KeyPairGenerator.getInstance("ML-KEM-768", BC).generateKeyPair();
        AlgorithmParameterSpec[] specs = {
            KEMGenerateSpec.builder().withPublicKey(bc.getPublic()).withAlgorithmName("AES").withKeySizeInBits(256)
                    .build(),
            new KEMExtractSpec(bc.getPrivate(), "AES", 256, new byte[1088])};
        for (AlgorithmParameterSpec spec : specs)
        {
            OSSLKey key = keptKey(Security.getProvider(JSL), spec);
            PKEYKeySpec keySpec = key.getSpec();
            String label = spec.getClass().getSimpleName();
            Assertions.assertEquals(false, keySpec.getSpecNI().getClass().getSimpleName().contains("FIPS"),
                    label + ": " + keySpec.getSpecNI().getClass().getName());
            Assertions.assertEquals("default", keySpec.getSpecNI().getKeyProvider(keySpec.getReference()), label);
            Assertions.assertNotNull(key.getSpec(), label);
        }
    }

}
