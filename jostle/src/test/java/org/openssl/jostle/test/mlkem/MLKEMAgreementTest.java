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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

/**
 * Cross-implementation agreement for Jostle's ML-KEM surface: JSL against
 * BouncyCastle, both directions, across every registered parameter set.
 *
 * <p>This is the family's SWEEP and its completeness GUARD. The depth stays
 * where it is — {@link MLKEMKTSCipherTest} keeps the KTS contract and
 * tampering coverage, {@link MLKEMTest} the key-encoding, seed and recovery
 * coverage.
 *
 * <p>Three interop surfaces, because Jostle exposes ML-KEM three ways and a
 * bug in one is invisible to the others: KEM via KeyGenerator, KTS via Cipher
 * (CMS KEMRecipientInfo), and the SPKI/PKCS#8 encodings that let a real peer
 * set either up.
 *
 * <p>Encapsulation is randomised, so byte-equality is unavailable as a
 * differentiator. Each direction is checked against the OTHER implementation
 * instead — a wrong-but-self-consistent Jostle cannot satisfy BC.
 */
public class MLKEMAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The three parameter sets, under the name both providers register. */
    private static final String[] PARAM_SETS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    private static final SecureRandom RANDOM = new SecureRandom();

    /** The KDF3/SHA-256 configuration BC's own MLKEMCipherSpi resolves to. */
    private static final KTSParameterSpec KTS_KDF3_SHA256 = new KTSParameterSpec.Builder("AES", 256)
            .withKdfAlgorithm(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                    org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_kdf_kdf3,
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
            .build();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

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

    private static KeyPair keyPair(String provider, String paramSet) throws Exception
    {
        return KeyPairGenerator.getInstance(paramSet, provider).generateKeyPair();
    }

    private static PublicKey importPublic(String provider, PublicKey k) throws Exception
    {
        return KeyFactory.getInstance("ML-KEM", provider)
                .generatePublic(new X509EncodedKeySpec(k.getEncoded()));
    }

    private static PrivateKey importPrivate(String provider, PrivateKey k) throws Exception
    {
        return KeyFactory.getInstance("ML-KEM", provider)
                .generatePrivate(new PKCS8EncodedKeySpec(k.getEncoded()));
    }

    // -----------------------------------------------------------------
    // 1. KEM: encapsulate / decapsulate, both directions
    // -----------------------------------------------------------------

    /**
     * JSL encapsulates to a BC-generated public key; BC must recover the same
     * secret. The key crosses as SPKI, which is what a real peer has — an
     * encapsulation that is self-consistent but not FIPS 203 produces a secret
     * BC cannot reach.
     */
    @Test
    public void kemEncapsulateJslDecapsulateBc() throws Exception
    {
        for (String paramSet : PARAM_SETS)
        {
            KeyPair bcPair = keyPair(BC, paramSet);

            KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", JSL);
            joGen.init(KEMGenerateSpec.builder()
                    .withKeySizeInBits(256)
                    .withPublicKey(importPublic(JSL, bcPair.getPublic()))
                    .withAlgorithmName("AES")
                    .build());
            SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation) joGen.generateKey();

            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new KEMExtractSpec.Builder(bcPair.getPrivate(),
                    encapsulated.getEncapsulation(), "AES", 256).withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation recovered =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();

            Assertions.assertTrue(Arrays.areEqual(encapsulated.getEncoded(), recovered.getEncoded()),
                    paramSet + ": BC decapsulated a different secret");
        }
    }

    /** The reverse: BC encapsulates, JSL decapsulates. A different code path. */
    @Test
    public void kemEncapsulateBcDecapsulateJsl() throws Exception
    {
        for (String paramSet : PARAM_SETS)
        {
            KeyPair joPair = keyPair(JSL, paramSet);

            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(
                    importPublic(BC, joPair.getPublic()), "AES", 256).withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation encapsulated =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();

            KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", JSL);
            joGen.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withPrivate(joPair.getPrivate())
                    .withEncapsulatedKey(encapsulated.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .build());
            SecretKeyWithEncapsulation recovered = (SecretKeyWithEncapsulation) joGen.generateKey();

            Assertions.assertTrue(Arrays.areEqual(encapsulated.getEncoded(), recovered.getEncoded()),
                    paramSet + ": JSL decapsulated a different secret");
        }
    }

    /**
     * The differentiator the two tests above need: an implementation returning
     * a constant would satisfy every agreement assertion. Two encapsulations
     * must differ, and one must not open under a different keypair.
     */
    @Test
    public void encapsulationIsKeyBoundAndFresh() throws Exception
    {
        KeyPair a = keyPair(JSL, "ML-KEM-768");
        KeyPair b = keyPair(JSL, "ML-KEM-768");

        SecretKeyWithEncapsulation first = encapsulate(a.getPublic());
        SecretKeyWithEncapsulation second = encapsulate(a.getPublic());

        Assertions.assertFalse(Arrays.areEqual(first.getEncoded(), second.getEncoded()),
                "two encapsulations produced the same secret");
        Assertions.assertFalse(Arrays.areEqual(first.getEncapsulation(), second.getEncapsulation()),
                "two encapsulations produced the same ciphertext");

        // Decapsulating A's ciphertext under B's key must not recover A's
        // secret. ML-KEM is implicitly rejecting, so this yields a different
        // secret rather than an error — which is exactly why it must be
        // asserted rather than assumed to throw.
        KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", JSL);
        joGen.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                .withPrivate(b.getPrivate())
                .withEncapsulatedKey(first.getEncapsulation())
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .build());
        SecretKeyWithEncapsulation wrongKey = (SecretKeyWithEncapsulation) joGen.generateKey();

        Assertions.assertFalse(Arrays.areEqual(first.getEncoded(), wrongKey.getEncoded()),
                "the wrong private key recovered the right secret");
    }

    private static SecretKeyWithEncapsulation encapsulate(PublicKey pub) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM", JSL);
        g.init(KEMGenerateSpec.builder()
                .withKeySizeInBits(256).withPublicKey(pub).withAlgorithmName("AES").build());
        return (SecretKeyWithEncapsulation) g.generateKey();
    }

    // -----------------------------------------------------------------
    // 2. KTS: Cipher wrap / unwrap, both directions
    // -----------------------------------------------------------------

    /**
     * The CMS KEMRecipientInfo surface, all three parameter sets, both
     * directions. {@link MLKEMKTSCipherTest} covers the contract in depth but
     * only at 768; this adds the other two.
     */
    @Test
    public void ktsWrapUnwrapAgreesBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("ktsWrapUnwrapAgreesBothDirections");

        for (String paramSet : PARAM_SETS)
        {
            KeyPair kp = keyPair(JSL, paramSet);
            KTSParameterSpec spec = KTS_KDF3_SHA256;

            byte[] cekBytes = new byte[32];
            sr.nextBytes(cekBytes);
            SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

            // JSL wraps, BC unwraps.
            Cipher joWrap = Cipher.getInstance("ML-KEM", JSL);
            joWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
            byte[] wrapped = joWrap.wrap(cek);

            Cipher bcUnwrap = Cipher.getInstance("ML-KEM", BC);
            bcUnwrap.init(Cipher.UNWRAP_MODE, importPrivate(BC, kp.getPrivate()), spec);
            Key viaBc = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertTrue(Arrays.areEqual(cekBytes, viaBc.getEncoded()),
                    paramSet + ": BC could not recover a JSL-wrapped CEK");

            // BC wraps, JSL unwraps.
            Cipher bcWrap = Cipher.getInstance("ML-KEM", BC);
            bcWrap.init(Cipher.WRAP_MODE, importPublic(BC, kp.getPublic()), spec);
            byte[] bcWrapped = bcWrap.wrap(cek);

            Cipher joUnwrap = Cipher.getInstance("ML-KEM", JSL);
            joUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
            Key viaJsl = joUnwrap.unwrap(bcWrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertTrue(Arrays.areEqual(cekBytes, viaJsl.getEncoded()),
                    paramSet + ": JSL could not recover a BC-wrapped CEK");
        }
    }

    // -----------------------------------------------------------------
    // 3. Key encodings cross in both directions
    // -----------------------------------------------------------------

    /**
     * Keys must survive a round trip through the other provider's KeyFactory
     * and still work. "Still work" is the load-bearing half: a key that
     * re-derives but has lost its parameter set passes a decode-succeeded
     * assertion and fails at the first operation.
     */
    @Test
    public void keyEncodingsCrossBothDirections() throws Exception
    {
        for (String paramSet : PARAM_SETS)
        {
            KeyPair joPair = keyPair(JSL, paramSet);
            KeyPair bcPair = keyPair(BC, paramSet);

            // JSL-encoded -> BC-decoded, then used.
            PublicKey bcPub = importPublic(BC, joPair.getPublic());
            PrivateKey bcPriv = importPrivate(BC, joPair.getPrivate());
            Assertions.assertTrue(Arrays.areEqual(joPair.getPublic().getEncoded(), bcPub.getEncoded()),
                    paramSet + ": BC re-encoded a JSL public key differently");
            Assertions.assertTrue(Arrays.areEqual(joPair.getPrivate().getEncoded(), bcPriv.getEncoded()),
                    paramSet + ": BC re-encoded a JSL private key differently");

            // BC-encoded -> JSL-decoded, then used.
            PublicKey joPub = importPublic(JSL, bcPair.getPublic());
            PrivateKey joPriv = importPrivate(JSL, bcPair.getPrivate());
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(), joPub.getEncoded()),
                    paramSet + ": JSL re-encoded a BC public key differently");
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPrivate().getEncoded(), joPriv.getEncoded()),
                    paramSet + ": JSL re-encoded a BC private key differently");

            // The keys still operate after the round trip.
            SecretKeyWithEncapsulation enc = encapsulate(joPub);
            KeyGenerator g = KeyGenerator.getInstance("ML-KEM", JSL);
            g.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withPrivate(joPriv)
                    .withEncapsulatedKey(enc.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .build());
            SecretKeyWithEncapsulation back = (SecretKeyWithEncapsulation) g.generateKey();
            Assertions.assertTrue(Arrays.areEqual(enc.getEncoded(), back.getEncoded()),
                    paramSet + ": a round-tripped BC keypair no longer operates");
        }
    }

    // -----------------------------------------------------------------
    // 4. Completeness guards
    // -----------------------------------------------------------------

    private static final String[] GUARDED_TYPES = {"Cipher", "KeyFactory", "KeyGenerator", "KeyPairGenerator"};

    /**
     * Every ML-KEM service JSL registers is DRIVEN, with the surface
     * discovered from the provider rather than listed.
     *
     * <p>No covered list on purpose: one would drift, and deriving it from the
     * provider would compare the provider against itself. An unknown name
     * THROWS below, so a registration added later fails until someone teaches
     * it an operation.
     */
    @Test
    public void everyRegisteredMlKemServiceIsDriven() throws Exception
    {
        final KeyPair k512 = keyPair(JSL, "ML-KEM-512");
        final KeyPair k768 = keyPair(JSL, "ML-KEM-768");
        final KeyPair k1024 = keyPair(JSL, "ML-KEM-1024");

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.MLKEM_PREFIX, "ML-KEM (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        KeyPair kp = keyForName(alg, k512, k768, k1024);
                        if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            // A bare name pins no parameter set, so it must be
                            // told one — the width-specific names must not.
                            if (!pinsParameterSet(alg))
                            {
                                kpg.initialize(MLKEMParameterSpec.ml_kem_768);
                            }
                            Assertions.assertNotNull(kpg.generateKeyPair());
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            KeyFactory kf = KeyFactory.getInstance(alg, JSL);
                            PublicKey pub = kf.generatePublic(
                                    new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                            Assertions.assertTrue(Arrays.areEqual(
                                    kp.getPublic().getEncoded(), pub.getEncoded()), alg);
                        }
                        else if ("KeyGenerator".equals(type))
                        {
                            KeyGenerator g = KeyGenerator.getInstance(alg, JSL);
                            g.init(KEMGenerateSpec.builder().withKeySizeInBits(256)
                                    .withPublicKey(kp.getPublic()).withAlgorithmName("AES").build());
                            Assertions.assertNotNull(g.generateKey());
                        }
                        else if ("Cipher".equals(type))
                        {
                            byte[] cekBytes = new byte[32];
                            new SecureRandom().nextBytes(cekBytes);
                            SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");
                            Cipher w = Cipher.getInstance(alg, JSL);
                            w.init(Cipher.WRAP_MODE, kp.getPublic(), KTS_KDF3_SHA256);
                            byte[] wrapped = w.wrap(cek);
                            Cipher u = Cipher.getInstance(alg, JSL);
                            u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), KTS_KDF3_SHA256);
                            Assertions.assertTrue(Arrays.areEqual(cekBytes,
                                    u.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded()), alg);
                        }
                        else
                        {
                            throw new IllegalStateException("no drive defined for " + type + "." + alg
                                    + " — teach this driver rather than letting it go unexercised");
                        }
                    }
                });
    }

    /**
     * The parameter set a registered name pins, from the name. The OID arc
     * {@code 2.16.840.1.101.3.4.4.{1,2,3}} is 512 / 768 / 1024; a bare name
     * pins nothing, so 768 serves.
     */
    private static boolean pinsParameterSet(String alg)
    {
        String n = alg.toUpperCase(Locale.ROOT);
        return n.contains("512") || n.contains("768") || n.contains("1024")
                || n.contains("2.16.840.1.101.3.4.4.");
    }

    private static KeyPair keyForName(String alg, KeyPair k512, KeyPair k768, KeyPair k1024)
    {
        String n = alg.toUpperCase(Locale.ROOT);
        if (n.contains("512") || n.endsWith(".4.4.1"))
        {
            return k512;
        }
        if (n.contains("1024") || n.endsWith(".4.4.3"))
        {
            return k1024;
        }
        return k768;
    }
}
