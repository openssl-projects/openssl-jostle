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

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;

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

    /**
     * The KDF3/SHA-256 KDF AlgorithmIdentifier BC's own MLKEMCipherSpi resolves
     * to. BC and Jostle now each accept only their own spec type directly, so
     * this is built into the provider-appropriate spec at each call site via
     * {@link #kts(String)}.
     */
    private static final AlgorithmIdentifier KDF3_SHA256 = new AlgorithmIdentifier(
            X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

    private static AlgorithmParameterSpec kts(String provider) throws IOException
    {
        if (BC.equals(provider))
        {
            // KTSParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            return new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AES", 256)
                    .withKdfAlgorithm(KDF3_SHA256).build();
        }
        return new KTSParameterSpec.Builder("AES", 256).withKdfAlgorithm(KDF3_SHA256.getEncoded()).build();
    }

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
                    .withNoKdf().build());
            SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation) joGen.generateKey();

            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new KEMExtractSpec.Builder(bcPair.getPrivate(),
                    encapsulated.getEncapsulation(), "AES", 256).withKdfAlgorithm(null).build());
            // SecretKeyWithEncapsulation is qualified where BouncyCastle's is meant: jostle's of that name is imported
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
            // KEMGenerateSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(
                    importPublic(BC, joPair.getPublic()), "AES", 256).withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation encapsulated =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();

            KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", JSL);
            // KEMExtractSpec is qualified where jostle's is meant: BouncyCastle's of that name is imported
            joGen.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withPrivate(joPair.getPrivate())
                    .withEncapsulatedKey(encapsulated.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withNoKdf().build());
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
                .withNoKdf().build());
        SecretKeyWithEncapsulation wrongKey = (SecretKeyWithEncapsulation) joGen.generateKey();

        Assertions.assertFalse(Arrays.areEqual(first.getEncoded(), wrongKey.getEncoded()),
                "the wrong private key recovered the right secret");
    }

    private static SecretKeyWithEncapsulation encapsulate(PublicKey pub) throws Exception
    {
        KeyGenerator g = KeyGenerator.getInstance("ML-KEM", JSL);
        g.init(KEMGenerateSpec.builder()
                .withKeySizeInBits(256).withPublicKey(pub).withAlgorithmName("AES").withNoKdf().build());
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

            byte[] cekBytes = new byte[32];
            sr.nextBytes(cekBytes);
            SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

            // JSL wraps, BC unwraps.
            Cipher joWrap = Cipher.getInstance("ML-KEM", JSL);
            joWrap.init(Cipher.WRAP_MODE, kp.getPublic(), kts(JSL));
            byte[] wrapped = joWrap.wrap(cek);

            Cipher bcUnwrap = Cipher.getInstance("ML-KEM", BC);
            bcUnwrap.init(Cipher.UNWRAP_MODE, importPrivate(BC, kp.getPrivate()), kts(BC));
            Key viaBc = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Assertions.assertTrue(Arrays.areEqual(cekBytes, viaBc.getEncoded()),
                    paramSet + ": BC could not recover a JSL-wrapped CEK");

            // BC wraps, JSL unwraps.
            Cipher bcWrap = Cipher.getInstance("ML-KEM", BC);
            bcWrap.init(Cipher.WRAP_MODE, importPublic(BC, kp.getPublic()), kts(BC));
            byte[] bcWrapped = bcWrap.wrap(cek);

            Cipher joUnwrap = Cipher.getInstance("ML-KEM", JSL);
            joUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kts(JSL));
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
                    .withNoKdf().build());
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
                                    .withPublicKey(kp.getPublic()).withAlgorithmName("AES").withNoKdf().build());
                            Assertions.assertNotNull(g.generateKey());
                        }
                        else if ("Cipher".equals(type))
                        {
                            byte[] cekBytes = new byte[32];
                            new SecureRandom().nextBytes(cekBytes);
                            SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");
                            Cipher w = Cipher.getInstance(alg, JSL);
                            w.init(Cipher.WRAP_MODE, kp.getPublic(), kts(JSL));
                            byte[] wrapped = w.wrap(cek);
                            Cipher u = Cipher.getInstance(alg, JSL);
                            u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kts(JSL));
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

    /**
     * The generic generators used without initialize() agree with BouncyCastle's generic generator used the same
     * way: BouncyCastle reads the same parameter set from our encoding as its own default key carries (ML-KEM-768),
     * and a secret encapsulated by either side to the other's default key is recovered.
     */
    @Test
    public void bareGenericGeneratorsAgreeWithBouncyCastlesDefault() throws Exception
    {
        KeyPair bc = KeyPairGenerator.getInstance("ML-KEM", BC).generateKeyPair();
        String bcDefault = ((MLKEMKey) bc.getPublic()).getParameterSpec().getName();
        Assertions.assertEquals("ML-KEM-768", bcDefault, "BouncyCastle's default moved");
        for (String name : new String[]{"ML-KEM", "MLKEM"})
        {
            KeyPair jsl = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();
            PublicKey jslPubAtBc = importPublic(BC, jsl.getPublic());
            Assertions.assertEquals(bcDefault, ((MLKEMKey) jslPubAtBc).getParameterSpec().getName(), name);

            KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", JSL);
            joGen.init(KEMGenerateSpec.builder()
                    .withKeySizeInBits(256)
                    .withPublicKey(importPublic(JSL, bc.getPublic()))
                    .withAlgorithmName("AES")
                    .withNoKdf().build());
            SecretKeyWithEncapsulation toBc = (SecretKeyWithEncapsulation) joGen.generateKey();
            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new KEMExtractSpec.Builder(bc.getPrivate(), toBc.getEncapsulation(), "AES", 256)
                    .withKdfAlgorithm(null).build());
            Assertions.assertTrue(Arrays.areEqual(toBc.getEncoded(), bcGen.generateKey().getEncoded()),
                    name + ": BC decapsulated a different secret");

            bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(jslPubAtBc, "AES", 256)
                    .withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation toJsl =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();
            joGen = KeyGenerator.getInstance("ML-KEM", JSL);
            joGen.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withPrivate(jsl.getPrivate())
                    .withEncapsulatedKey(toJsl.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withNoKdf().build());
            Assertions.assertTrue(Arrays.areEqual(toJsl.getEncoded(), joGen.generateKey().getEncoded()),
                    name + ": JSL decapsulated a different secret");
        }
    }

    /** BouncyCastle's private key with only the expanded form, as PKCS#8. */
    private static byte[] bcExpandedOnly(KeyPair bc)
    {
        // MLKEMPrivateKey is qualified where BouncyCastle's is meant: jostle's of that name is imported
        return ((org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey) bc.getPrivate()).getPrivateKey(false)
                .getEncoded();
    }

    /**
     * BC's expanded-only PKCS#8 decodes on JSL, stays expanded and re-encodes byte-equal. The import runs a pairwise
     * test that draws entropy, so it needs the decode's RandSource; BC decodes the same bytes, so both halves agree.
     */
    @Test
    public void bouncyCastlesExpandedOnlyEncodingDecodesAndStaysExpanded() throws Exception
    {
        for (String paramSet : PARAM_SETS)
        {
            KeyPair bcPair = keyPair(BC, paramSet);
            byte[] expanded = bcExpandedOnly(bcPair);
            Assertions.assertEquals(0x04, KeyInfoCanonicalizer.privateKeyFirstByte(expanded), paramSet);

            PrivateKey ours = KeyFactory.getInstance("ML-KEM", JSL)
                    .generatePrivate(new PKCS8EncodedKeySpec(expanded));
            Assertions.assertNull(((MLKEMPrivateKey) ours).getSeed(), paramSet);
            Assertions.assertArrayEquals(expanded, ours.getEncoded(), paramSet);
            Assertions.assertArrayEquals(expanded,
                    KeyFactory.getInstance("ML-KEM", BC).generatePrivate(new PKCS8EncodedKeySpec(expanded))
                            .getEncoded(), paramSet);

            // The decoded key works: it opens BC's encapsulation to BC's secret.
            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", BC);
            // KEMGenerateSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(bcPair.getPublic(), "AES", 256)
                    .withKdfAlgorithm(null).build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation sent =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey();
            KeyGenerator joGen = KeyGenerator.getInstance("ML-KEM", JSL);
            // KEMExtractSpec is qualified where jostle's is meant: BouncyCastle's of that name is imported
            joGen.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withPrivate(ours)
                    .withEncapsulatedKey(sent.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withNoKdf().build());
            Assertions.assertArrayEquals(sent.getEncoded(), joGen.generateKey().getEncoded(), paramSet);
        }
    }

    private static MLKEMParameterSpec[] joSpec = new MLKEMParameterSpec[]{
            MLKEMParameterSpec.ml_kem_512,
            MLKEMParameterSpec.ml_kem_768,
            MLKEMParameterSpec.ml_kem_1024,

    };

    // MLKEMParameterSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
    private static org.bouncycastle.jcajce.spec.MLKEMParameterSpec[] bcSpec =
            new org.bouncycastle.jcajce.spec.MLKEMParameterSpec[]{
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_512,
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_768,
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_1024,
    };

    private static Map<org.bouncycastle.jcajce.spec.MLKEMParameterSpec, MLKEMParameterSpec> bcToJostle =
            new HashMap<>();

    private static Map<MLKEMParameterSpec, org.bouncycastle.jcajce.spec.MLKEMParameterSpec> jostleToBc =
            new HashMap<>();

    static
    {
        for (int i = 0; i < joSpec.length; i++)
        {
            bcToJostle.put(bcSpec[i], joSpec[i]);
            jostleToBc.put(joSpec[i], bcSpec[i]);
        }
    }

    @Test
    public void testKeyExchangeJSLToBC() throws Exception
    {
        for (int i = 0; i < joSpec.length; i++)
        {

            //
            // BC receiver
            //
            KeyPairGenerator bcGen = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            bcGen.initialize(bcSpec[i]);
            KeyPair receiverKeyPair = bcGen.generateKeyPair();


            //
            // Use JSL to reconstitute encoded BC key and then encapsulate a key
            //
            KeyFactory joKeyFactory = KeyFactory.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            PublicKey receiverRecoveredPublicKey =
                    joKeyFactory.generatePublic(new X509EncodedKeySpec(receiverKeyPair.getPublic().getEncoded()));

            KeyGenerator joKeyGenerator = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            joKeyGenerator.init(KEMGenerateSpec.builder()
                    .withKeySizeInBits(256)
                    .withPublicKey(receiverRecoveredPublicKey)
                    .withAlgorithmName("AES")
                    .withNoKdf().build()
            );
            SecretKeyWithEncapsulation encapsulation = (SecretKeyWithEncapsulation) joKeyGenerator.generateKey();


            //
            // Use BC to decapsulate the key
            //
            KeyGenerator serverKeyFactory = KeyGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            // KEMExtractSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            serverKeyFactory.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder(receiverKeyPair.getPrivate(),
                    encapsulation.getEncapsulation(), "AES", 256)
                    .withKdfAlgorithm(null)
                    .build());
            // SecretKeyWithEncapsulation is qualified where BouncyCastle's is meant: jostle's of that name is imported
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation decapsulatedKey =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) serverKeyFactory.generateKey();

            Assertions.assertArrayEquals(encapsulation.getEncoded(), decapsulatedKey.getEncoded());
            Assertions.assertArrayEquals(encapsulation.getEncapsulation(), decapsulatedKey.getEncapsulation());

        }
    }

    @Test
    public void testKeyExchangeBCToJSL() throws Exception
    {
        for (int i = 0; i < joSpec.length; i++)
        {

            //
            // JSL receiver
            //
            KeyPairGenerator bcGen = KeyPairGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            bcGen.initialize(joSpec[i]);
            KeyPair receiverKeyPair = bcGen.generateKeyPair();


            //
            // Use BC to encapsulate the key, verify BC can reconstitute and encoded public key from JSL
            //
            KeyFactory joKeyFactory = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey receiverRecoveredPublicKey =
                    joKeyFactory.generatePublic(new X509EncodedKeySpec(receiverKeyPair.getPublic().getEncoded()));

            KeyGenerator joKeyGenerator = KeyGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            // KEMGenerateSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            joKeyGenerator.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(receiverRecoveredPublicKey,
                    "AES", 256)
                    .withKdfAlgorithm(null)
                    .build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation encapsulation =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) joKeyGenerator.generateKey();


            //
            // Use JSL to decapsulate the key
            //
            KeyGenerator serverKeyFactory = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            // KEMExtractSpec is qualified where jostle's is meant: BouncyCastle's of that name is imported
            serverKeyFactory.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withEncapsulatedKey(encapsulation.getEncapsulation())
                    .withAlgorithmName("AES")
                    .withPrivate(receiverKeyPair.getPrivate())
                    .withKeySizeInBits(256).withNoKdf().build()
            );
            SecretKeyWithEncapsulation decapsulatedKey = (SecretKeyWithEncapsulation) serverKeyFactory.generateKey();

            Assertions.assertArrayEquals(encapsulation.getEncoded(), decapsulatedKey.getEncoded());
            Assertions.assertArrayEquals(encapsulation.getEncapsulation(), decapsulatedKey.getEncapsulation());


            //
            // Vandalise encapsulation must fail
            //

            byte[] vandalised = decapsulatedKey.getEncapsulation();
            vandalised[0] ^= 1;
            // KEMExtractSpec is qualified where jostle's is meant: BouncyCastle's of that name is imported
            serverKeyFactory.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withEncapsulatedKey(vandalised)
                    .withAlgorithmName("AES")
                    .withPrivate(receiverKeyPair.getPrivate())
                    .withKeySizeInBits(256).withNoKdf().build()
            );
            SecretKeyWithEncapsulation vandalisedDecapsulatedKey =
                    (SecretKeyWithEncapsulation) serverKeyFactory.generateKey();
            Assertions.assertFalse(Arrays.areEqual(encapsulation.getEncoded(), vandalisedDecapsulatedKey.getEncoded()));

        }
    }

    @Test
    public void keyFactoryByNameTest() throws Exception
    {
        String[] names = new String[]{
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
        };


        for (int t = 0; t < names.length; t++)
        {
            String name = names[t];

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(name, BouncyCastleProvider.PROVIDER_NAME);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            {
                KeyFactory keyFactory = KeyFactory.getInstance(name, JostleProvider.PROVIDER_NAME);
                PublicKey pubK = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                PrivateKey privK =
                        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                Assertions.assertEquals(name, pubK.getAlgorithm());
                Assertions.assertEquals(name, privK.getAlgorithm());
            }

            //
            // Check it will actually fail
            //

            {
                String failingName = names[(t + 1) % names.length];

                try
                {
                    KeyFactory keyFactory = KeyFactory.getInstance(failingName, JostleProvider.PROVIDER_NAME);
                    keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

                    Assertions.fail();
                } catch (InvalidKeySpecException ikse)
                {
                    Assertions.assertEquals("expected " + failingName + " but got " + name, ikse.getMessage());
                }

            }

        }


    }

    @Test
    public void testSeedOnlyKeyEncoding() throws Exception
    {
        for (MLKEMParameterSpec spec : joSpec)
        {
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec bcSpec = jostleToBc.get(spec);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLKEM", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();

            MLKEMPrivateKey privKey = (MLKEMPrivateKey) keyPair.getPrivate();
            byte[] privateKeySeedOnly = privKey.getPrivateKey(true).getEncoded();

            System.out.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(privateKeySeedOnly), true));


            Assertions.assertEquals(86, privateKeySeedOnly.length);

            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance(bcSpec.getName(), BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeySeedOnly));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));


            KeyGenerator encapsulator = KeyGenerator.getInstance(bcSpec.getName(), BouncyCastleProvider.PROVIDER_NAME);

            org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder genBuild =
                    new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(pubKeyBC, "AES", 256);
            encapsulator.init(genBuild.build());

            org.bouncycastle.jcajce.SecretKeyWithEncapsulation  secretKey =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation ) encapsulator.generateKey();


            KeyGenerator extractor = KeyGenerator.getInstance(bcSpec.getName(), BouncyCastleProvider.PROVIDER_NAME);

            org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder exBuild =
                    new org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder(privKeyBC, secretKey.getEncapsulation(),
                            "AES", 256);

            extractor.init(exBuild.build());


            org.bouncycastle.jcajce.SecretKeyWithEncapsulation  recoveredKey =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation ) extractor.generateKey();

            Assertions.assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncapsulation(), recoveredKey.getEncapsulation());


        }
    }

    @Test
    public void testKeyGen() throws Exception
    {
        for (MLKEMParameterSpec spec : joSpec)
        {
            org.bouncycastle.jcajce.spec.MLKEMParameterSpec bcSpec = jostleToBc.get(spec);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLKEM", JostleProvider.PROVIDER_NAME);
            keyGen.initialize(spec);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            //
            // Verify encoded key can be handled by BC and is usable
            //
            KeyFactory factory = KeyFactory.getInstance(bcSpec.getName(), BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey privKeyBC = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey pubKeyBC = factory.generatePublic(new X509EncodedKeySpec(publicKey));

            KeyGenerator encapsulator = KeyGenerator.getInstance(bcSpec.getName(), BouncyCastleProvider.PROVIDER_NAME);
            encapsulator.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec.Builder(pubKeyBC, "AES", 256)
                    .withKdfAlgorithm(null)
                    .build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation secretKey =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) encapsulator.generateKey();

            KeyGenerator extractor = KeyGenerator.getInstance(bcSpec.getName(), BouncyCastleProvider.PROVIDER_NAME);
            extractor.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec.Builder(privKeyBC,
                    secretKey.getEncapsulation(), "AES", 256)
                    .withKdfAlgorithm(null)
                    .build());
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation recoveredKey =
                    (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) extractor.generateKey();

            Assertions.assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncapsulation(), recoveredKey.getEncapsulation());
        }
    }

    @Test
    public void testKeyRecovery() throws Exception
    {
        // BC keygen -> Jostle KeyFactory PKCS8/X509 import -> Jostle encap/decap.
        // Exercises the asn1_writer_decode_*_key path (now bound to Jostle's
        // libctx via d2i_PrivateKey_ex / d2i_PUBKEY_ex).

        for (org.bouncycastle.jcajce.spec.MLKEMParameterSpec bcs : bcSpec)
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("MLKEM", BouncyCastleProvider.PROVIDER_NAME);
            keyGen.initialize(bcs);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] publicKeyX509 = keyPair.getPublic().getEncoded();
            byte[] privateKeyPKCS8 = keyPair.getPrivate().getEncoded();

            KeyFactory jostleFactory = KeyFactory.getInstance("MLKEM", JostleProvider.PROVIDER_NAME);
            PrivateKey privateKey = jostleFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyPKCS8));
            PublicKey publicKey = jostleFactory.generatePublic(new X509EncodedKeySpec(publicKeyX509));

            KeyGenerator encapsulator = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            encapsulator.init(KEMGenerateSpec.builder()
                    .withPublicKey(publicKey)
                    .withKeySizeInBits(256)
                    .withAlgorithmName("AES").withNoKdf().build());
            SecretKeyWithEncapsulation secretKey = (SecretKeyWithEncapsulation) encapsulator.generateKey();

            KeyGenerator extractor = KeyGenerator.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            // KEMExtractSpec is qualified where jostle's is meant: BouncyCastle's of that name is imported
            extractor.init(org.openssl.jostle.jcajce.spec.KEMExtractSpec.builder()
                    .withPrivate(privateKey)
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(256)
                    .withEncapsulatedKey(secretKey.getEncapsulation())
                    .withNoKdf().build());
            SecretKeyWithEncapsulation recoveredKey = (SecretKeyWithEncapsulation) extractor.generateKey();

            Assertions.assertArrayEquals(secretKey.getEncoded(), recoveredKey.getEncoded());
            Assertions.assertArrayEquals(secretKey.getEncapsulation(), recoveredKey.getEncapsulation());
        }
    }

    /** A wrong-length encapsulation is refused before the native call, with the type BouncyCastle throws. */
    @Test
    public void mlKem_wrongLengthEncapsulation_refusedAsBouncyCastleDoes() throws Exception
    {
        Provider bc = new BouncyCastleProvider();
        for (String name : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair ours = KeyPairGenerator.getInstance(name, JSL).generateKeyPair();
            byte[] enc = KemExtractLengthTest.encapsulation(name, JSL, ours);

            KeyPair theirs = KeyPairGenerator.getInstance(name, bc).generateKeyPair();
            KeyGenerator bcGen = KeyGenerator.getInstance("ML-KEM", bc);
            // KEMGenerateSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
            bcGen.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(theirs.getPublic(), "AES", 256));
            // SecretKeyWithEncapsulation is qualified where BouncyCastle's is meant: jostle's of that name is imported
            byte[] bcEnc = ((org.bouncycastle.jcajce.SecretKeyWithEncapsulation) bcGen.generateKey())
                    .getEncapsulation();

            for (int delta : new int[]{-1, 1, -enc.length})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> KemExtractLengthTest.extract(name, JSL, ours, Arrays.copyOf(enc, enc.length + delta),
                                256),
                        name + " delta " + delta);
                Assertions.assertEquals("encapsulation wrong length: " + (enc.length + delta) + " bytes, "
                        + name.replace('-', '_') + " takes " + enc.length, e.getMessage());

                // BouncyCastle's half, measured live.
                KeyGenerator x = KeyGenerator.getInstance("ML-KEM", bc);
                // KEMExtractSpec is qualified where BouncyCastle's is meant: jostle's of that name is imported
                x.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec(theirs.getPrivate(),
                        Arrays.copyOf(bcEnc, bcEnc.length + delta), "AES", 256));
                Assertions.assertThrows(IllegalArgumentException.class, x::generateKey, "BC " + name);
            }

            // Control: the whole encapsulation extracts.
            Assertions.assertNotNull(KemExtractLengthTest.extract(name, JSL, ours, enc, 256));
        }
    }

    /**
     * A key keeps the private key form it was decoded from: a seed-only PKCS#8, ours or BouncyCastle's, re-encodes
     * seed-only and byte-equal on both providers, both ways; a generated key encodes both forms, as BouncyCastle's.
     */
    @Test
    public void aSeedOnlyEncodingRoundTripsSeedOnlyBothWays() throws Exception
    {
        for (String paramSet : PARAM_SETS)
        {
            KeyPair ourPair = keyPair(JSL, paramSet);
            KeyPair bcPair = keyPair(BC, paramSet);
            Assertions.assertEquals(KeyInfoCanonicalizer.FORM_BOTH,
                    KeyInfoCanonicalizer.privateKeyFirstByte(ourPair.getPrivate().getEncoded()), paramSet);
            Assertions.assertEquals(KeyInfoCanonicalizer.FORM_BOTH,
                    KeyInfoCanonicalizer.privateKeyFirstByte(bcPair.getPrivate().getEncoded()), paramSet);

            byte[] ourSeed = ((MLKEMPrivateKey) ourPair.getPrivate()).getPrivateKey(true).getEncoded();
            // MLKEMPrivateKey is qualified where BouncyCastle's is meant: jostle's of that name is imported
            byte[] bcSeed = ((org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey) bcPair.getPrivate())
                    .getPrivateKey(true).getEncoded();
            for (byte[] seedOnly : new byte[][]{ourSeed, bcSeed})
            {
                Assertions.assertEquals(KeyInfoCanonicalizer.FORM_SEED,
                        KeyInfoCanonicalizer.privateKeyFirstByte(seedOnly), paramSet);
                for (String provider : new String[]{JSL, BC})
                {
                    PrivateKey decoded = KeyFactory.getInstance("ML-KEM", provider)
                            .generatePrivate(new PKCS8EncodedKeySpec(seedOnly));
                    Assertions.assertArrayEquals(seedOnly, decoded.getEncoded(), paramSet + " through " + provider);
                }
            }
        }
    }

    /**
     * The KEM KeyGenerator takes only a spec: init(int) and init(SecureRandom) are InvalidParameterException naming
     * the spec form here, the type KeyGenerator.init declares; BouncyCastle throws an unchecked
     * UnsupportedOperationException. Both halves.
     */
    @Test
    public void initWithoutASpecIsRefusedTypedWhereBouncyCastleThrowsUnchecked() throws Exception
    {
        String message = "ML-KEM needs a KEMGenerateSpec or KEMExtractSpec; use init(AlgorithmParameterSpec)";
        KeyGenerator ours = KeyGenerator.getInstance("ML-KEM", JSL);
        Assertions.assertEquals(message,
                Assertions.assertThrows(InvalidParameterException.class, () -> ours.init(256)).getMessage());
        Assertions.assertEquals(message,
                Assertions.assertThrows(InvalidParameterException.class, () -> ours.init(RANDOM)).getMessage());

        KeyGenerator theirs = KeyGenerator.getInstance("ML-KEM", BC);
        Assertions.assertEquals("Operation not supported",
                Assertions.assertThrows(UnsupportedOperationException.class, () -> theirs.init(256)).getMessage());
        Assertions.assertEquals("Operation not supported",
                Assertions.assertThrows(UnsupportedOperationException.class, () -> theirs.init(RANDOM)).getMessage());
    }
}
