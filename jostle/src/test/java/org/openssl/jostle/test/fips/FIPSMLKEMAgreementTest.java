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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
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
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.SortedSet;

/**
 * Cross-provider agreement for the FIPS provider's ML-KEM surface: JSLFIPS vs
 * JSL and vs BouncyCastle, both directions.
 *
 * <p>The FIPS analogue of {@code mlkem/MLKEMAgreementTest}, not redundant with
 * it: this drives {@code libinterface_fips_*} through the FIPS lib ctx.
 * Mainline implements ML-KEM identically, so no output comparison distinguishes
 * them — {@code FIPSModuleIsActuallyUsedTest} asks the module directly instead.
 *
 * <p>Capability-gated: 3.1.2 implements no PQC, and that absence is checked
 * against the module rather than assumed. Also gated on {@code TEST_FIPS_LIB}.
 */
public class FIPSMLKEMAgreementTest
{
    private static final String FIPS = org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] PARAM_SETS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /** Class-level gate, so a test added later is gated too. */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Does the loaded module implement ML-KEM at all? 3.1.2 does not. */
    private static boolean moduleServesMlKem()
    {
        return Security.getProvider(FIPS).getService("KeyPairGenerator", "ML-KEM-768") != null;
    }

    private static void assumeMlKem()
    {
        org.junit.jupiter.api.Assumptions.assumeTrue(moduleServesMlKem(),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
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

    private static SecretKeyWithEncapsulation encapsulate(String provider, PublicKey pub) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM", provider);
        g.init(KEMGenerateSpec.builder()
                .withKeySizeInBits(256).withPublicKey(pub).withAlgorithmName("AES").build());
        return (SecretKeyWithEncapsulation) g.generateKey();
    }

    private static SecretKeyWithEncapsulation decapsulate(String provider, PrivateKey priv,
                                                          byte[] encapsulation) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM", provider);
        g.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                .withPrivate(priv)
                .withEncapsulatedKey(encapsulation)
                .withAlgorithmName("AES")
                .withKeySizeInBits(256)
                .build());
        return (SecretKeyWithEncapsulation) g.generateKey();
    }

    /** JSLFIPS encapsulates; JSL and BC must each recover the same secret. */
    @Test
    public void kemEncapsulateFipsDecapsulateJslAndBc() throws Exception
    {
        assumeMlKem();

        for (String paramSet : PARAM_SETS)
        {
            KeyPair kp = KeyPairGenerator.getInstance(paramSet, FIPS).generateKeyPair();
            SecretKeyWithEncapsulation enc = encapsulate(FIPS, kp.getPublic());

            // The private key crosses as PKCS#8 — the sanctioned route, since
            // its native handle is bound to the library that made it.
            SecretKeyWithEncapsulation viaJsl =
                    decapsulate(JSL, importPrivate(JSL, kp.getPrivate()), enc.getEncapsulation());
            Assertions.assertTrue(Arrays.areEqual(enc.getEncoded(), viaJsl.getEncoded()),
                    paramSet + ": JSL decapsulated a different secret");

            // JSLFIPS -> BC.
            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new KEMExtractSpec.Builder(importPrivate(BC, kp.getPrivate()),
                    enc.getEncapsulation(), "AES", 256).withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation viaBc =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();
            Assertions.assertTrue(Arrays.areEqual(enc.getEncoded(), viaBc.getEncoded()),
                    paramSet + ": BC decapsulated a different secret");
        }
    }

    /** The reverse: JSL and BC each encapsulate, JSLFIPS decapsulates. */
    @Test
    public void kemEncapsulateJslAndBcDecapsulateFips() throws Exception
    {
        assumeMlKem();

        for (String paramSet : PARAM_SETS)
        {
            KeyPair kp = KeyPairGenerator.getInstance(paramSet, FIPS).generateKeyPair();

            SecretKeyWithEncapsulation fromJsl = encapsulate(JSL, importPublic(JSL, kp.getPublic()));
            Assertions.assertTrue(Arrays.areEqual(fromJsl.getEncoded(),
                            decapsulate(FIPS, kp.getPrivate(), fromJsl.getEncapsulation()).getEncoded()),
                    paramSet + ": JSLFIPS could not decapsulate a JSL encapsulation");

            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(
                    importPublic(BC, kp.getPublic()), "AES", 256).withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation fromBc =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();
            Assertions.assertTrue(Arrays.areEqual(fromBc.getEncoded(),
                            decapsulate(FIPS, kp.getPrivate(), fromBc.getEncapsulation()).getEncoded()),
                    paramSet + ": JSLFIPS could not decapsulate a BC encapsulation");
        }
    }

    /** The KTS Cipher surface, JSLFIPS against BC, both directions. */
    @Test
    public void ktsWrapUnwrapAgreesWithBcBothDirections() throws Exception
    {
        assumeMlKem();
        SecureRandom sr = seededRandom("ktsWrapUnwrapAgreesWithBcBothDirections");

        for (String paramSet : PARAM_SETS)
        {
            KeyPair kp = KeyPairGenerator.getInstance(paramSet, FIPS).generateKeyPair();
            KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256)
                    .withKdfAlgorithm(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
                            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                    .build();

            byte[] cekBytes = new byte[32];
            sr.nextBytes(cekBytes);
            SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

            Cipher fipsWrap = Cipher.getInstance("ML-KEM", FIPS);
            fipsWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
            byte[] wrapped = fipsWrap.wrap(cek);

            Cipher bcUnwrap = Cipher.getInstance("ML-KEM", BC);
            bcUnwrap.init(Cipher.UNWRAP_MODE, importPrivate(BC, kp.getPrivate()), spec);
            Key viaBc = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertTrue(Arrays.areEqual(cekBytes, viaBc.getEncoded()),
                    paramSet + ": BC could not recover a JSLFIPS-wrapped CEK");

            Cipher bcWrap = Cipher.getInstance("ML-KEM", BC);
            bcWrap.init(Cipher.WRAP_MODE, importPublic(BC, kp.getPublic()), spec);
            byte[] bcWrapped = bcWrap.wrap(cek);

            Cipher fipsUnwrap = Cipher.getInstance("ML-KEM", FIPS);
            fipsUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
            Key viaFips = fipsUnwrap.unwrap(bcWrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertTrue(Arrays.areEqual(cekBytes, viaFips.getEncoded()),
                    paramSet + ": JSLFIPS could not recover a BC-wrapped CEK");
        }
    }

    /**
     * Key encodings cross between all three implementations, and still
     * operate — a key that decodes but has lost its parameter set passes a
     * decode-succeeded assertion and fails at first use.
     */
    @Test
    public void keyEncodingsCrossBetweenProviders() throws Exception
    {
        assumeMlKem();

        for (String paramSet : PARAM_SETS)
        {
            KeyPair fipsPair = KeyPairGenerator.getInstance(paramSet, FIPS).generateKeyPair();

            for (String other : new String[]{JSL, BC})
            {
                PublicKey pub = importPublic(other, fipsPair.getPublic());
                PrivateKey priv = importPrivate(other, fipsPair.getPrivate());
                Assertions.assertTrue(Arrays.areEqual(fipsPair.getPublic().getEncoded(), pub.getEncoded()),
                        paramSet + "/" + other + ": public key re-encoded differently");
                Assertions.assertTrue(Arrays.areEqual(fipsPair.getPrivate().getEncoded(), priv.getEncoded()),
                        paramSet + "/" + other + ": private key re-encoded differently");
            }

            // Still operates: JSLFIPS encapsulates to its own public key after a
            // round trip through JSL's encoder.
            PublicKey roundTripped = importPublic(FIPS,
                    importPublic(JSL, fipsPair.getPublic()));
            SecretKeyWithEncapsulation enc = encapsulate(FIPS, roundTripped);
            Assertions.assertTrue(Arrays.areEqual(enc.getEncoded(),
                            decapsulate(FIPS, fipsPair.getPrivate(), enc.getEncapsulation()).getEncoded()),
                    paramSet + ": a round-tripped public key no longer operates");
        }
    }

    // -----------------------------------------------------------------
    // Completeness guard
    // -----------------------------------------------------------------

    private static final String[] GUARDED_TYPES = {"Cipher", "KeyFactory", "KeyGenerator", "KeyPairGenerator"};

    /**
     * Every ML-KEM service JSLFIPS registers is DRIVEN, discovered rather than
     * listed. Absence is checked against the module, not allowed: skipping
     * would let a bug that dropped a working algorithm pass.
     */
    @Test
    public void everyRegisteredMlKemServiceIsDriven() throws Exception
    {
        Provider provider = Security.getProvider(FIPS);

        if (!moduleServesMlKem())
        {
            SortedSet<String> registered =
                    ProviderSurfaceGuard.registeredSurface(provider, CipherFamilies.MLKEM_PREFIX, GUARDED_TYPES);
            Assertions.assertTrue(registered.isEmpty(),
                    "the module implements no ML-KEM, yet JSLFIPS registers: " + registered);
            return;
        }

        final KeyPair k512 = KeyPairGenerator.getInstance("ML-KEM-512", FIPS).generateKeyPair();
        final KeyPair k768 = KeyPairGenerator.getInstance("ML-KEM-768", FIPS).generateKeyPair();
        final KeyPair k1024 = KeyPairGenerator.getInstance("ML-KEM-1024", FIPS).generateKeyPair();
        final SecureRandom sr = new SecureRandom();

        ProviderSurfaceGuard.assertEveryServiceDriven(provider, CipherFamilies.MLKEM_PREFIX,
                "ML-KEM (JSLFIPS)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        String n = alg.toUpperCase(java.util.Locale.ROOT);
                        KeyPair kp = (n.contains("512") || n.endsWith(".4.4.1")) ? k512
                                : (n.contains("1024") || n.endsWith(".4.4.3")) ? k1024 : k768;

                        if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, FIPS);
                            // A bare name pins no parameter set and must be told one.
                            if (!(n.contains("512") || n.contains("768") || n.contains("1024")
                                    || n.contains("2.16.840.1.101.3.4.4.")))
                            {
                                kpg.initialize(org.openssl.jostle.jcajce.spec.MLKEMParameterSpec.ml_kem_768);
                            }
                            Assertions.assertNotNull(kpg.generateKeyPair(), alg);
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            Assertions.assertNotNull(KeyFactory.getInstance(alg, FIPS)
                                    .generatePublic(new X509EncodedKeySpec(
                                            kp.getPublic().getEncoded())), alg);
                        }
                        else if ("KeyGenerator".equals(type))
                        {
                            KeyGenerator g = KeyGenerator.getInstance(alg, FIPS);
                            g.init(KEMGenerateSpec.builder().withKeySizeInBits(256)
                                    .withPublicKey(kp.getPublic()).withAlgorithmName("AES").build());
                            Assertions.assertNotNull(g.generateKey(), alg);
                        }
                        else if ("Cipher".equals(type))
                        {
                            byte[] cekBytes = new byte[32];
                            sr.nextBytes(cekBytes);
                            SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");
                            KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256)
                                    .withKdfAlgorithm(new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
                                            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                                    .build();
                            Cipher w = Cipher.getInstance(alg, FIPS);
                            w.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
                            byte[] wrapped = w.wrap(cek);
                            Cipher u = Cipher.getInstance(alg, FIPS);
                            u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
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
}
