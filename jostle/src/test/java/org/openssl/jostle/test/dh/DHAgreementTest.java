/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.dh;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
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
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-provider agreement for the WHOLE base-provider ({@code JSL}) DH
 * surface, against BouncyCastle.
 * <p>
 * Non-FIPS counterpart of {@link
 * org.openssl.jostle.test.fips.FIPSDHAgreementTest}. It is NOT the same pairing
 * as {@link DHKeyAgreementTest}, which pairs with {@code
 * FIPSDHKeyAgreementTest} and covers the KeyAgreement state machine; this class
 * is the family sweep over all five registered JCA types.
 * <p>
 * <b>What "agrees" means differs by type.</b>
 * <ol>
 * <li><b>KeyAgreement</b> — the shared secret, and the RFC 2631 KEK derived
 * from it, are deterministic functions of the two keys (and the UKM), so
 * agreement IS byte-equality.</li>
 * <li><b>KeyFactory</b> and <b>AlgorithmParameters</b> — byte-equality of the
 * encoding, both directions.</li>
 * <li><b>AlgorithmParameterGenerator</b> — a safe-prime SEARCH, so its output
 * is random and there is nothing to compare byte-for-byte. Agreement is
 * CROSS-ACCEPTANCE: BC must read the parameters back unchanged and build a
 * working keypair on them.</li>
 * </ol>
 * <b>Interop reference order</b> (CLAUDE.md): BC's JCE serves BOTH registered
 * agreements, so both use it — {@code DHWITHRFC2631KDF} through BC's ESDH OID
 * rather than that name, see {@link #BC_ESDH_OID}. The RFC 2631 KEK is
 * additionally compared against BC's lightweight {@code DHKEKGenerator}, a
 * second independent reference through a different BC code path.
 * <p>
 * <b>Settled ground this class leans on rather than re-litigates.</b> The
 * X9.42-versus-PKCS#3 q-preservation decisions live in {@link DHX942Test}; the
 * state-machine, offset-write and foreign-key rejections live in {@link
 * DHKeyAgreementTest}; the FIPS q-less refusal at derive-init and the
 * named-group substitution guard live in the FIPS classes. This class uses the
 * default PKCS#3 form {@code initialize(2048)} produces and asserts breadth.
 * <p>
 * Inputs come from a per-test SHA1PRNG whose seed is logged.
 */
public class DHAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The five JCA types {@code ProvDH} registers under. */
    private static final String[] GUARDED_TYPES = {
            "AlgorithmParameterGenerator", "AlgorithmParameters",
            "KeyAgreement", "KeyFactory", "KeyPairGenerator"
    };

    /**
     * {@code initialize(2048)} resolves to the ffdhe2048 named group, so key
     * generation is instant. This is NOT the same code path as {@link
     * AlgorithmParameterGenerator}, which performs a real safe-prime search —
     * see {@link #PARAMGEN_BITS}.
     */
    private static final int KEY_BITS = 2048;

    /**
     * The size the one AlgorithmParameterGenerator test runs at, and it is a
     * COST decision rather than a security statement. Measured on this machine:
     * a 2048-bit safe-prime search took 11.5 s and then 31 s on a second run —
     * it is a randomised search, so its cost is unbounded in the tail. 1024
     * takes ~0.3 s. The codec and cross-acceptance path being asserted does not
     * vary with the size, and every KEY in this class is 2048-bit.
     */
    private static final int PARAMGEN_BITS = 1024;

    /** id-aes256-wrap, giving a 32-byte KEK. */
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";

    /**
     * BouncyCastle's JCE name for the RFC 2631 agreement: id-alg-ESDH.
     * <p>
     * BC does NOT register the string {@code DHWITHRFC2631KDF} — enumerating
     * its KeyAgreement names shows the X9.42 {@code DHWITHSHA*KDF} family and
     * no RFC 2631 spelling — but it DOES serve the algorithm under this OID.
     * Scanning the name list alone says "BC has no JCE name for it", which is
     * false; that is the third time in this arc that an OID spelling falsified
     * a name-based conclusion.
     */
    private static final String BC_ESDH_OID = "1.2.840.113549.1.9.16.3.5";

    /**
     * Registered KeyAgreement names, mapped to BouncyCastle's JCE spelling.
     * Both are served by BC's JCE, so no lightweight fallback is needed for
     * the reference order — the lightweight generator is used as a SECOND,
     * independent reference rather than as a substitute.
     */
    private static final Map<String, String> BC_JCE_KEY_AGREEMENT =
            new LinkedHashMap<String, String>();

    static
    {
        BC_JCE_KEY_AGREEMENT.put("DH", "DH");
        BC_JCE_KEY_AGREEMENT.put("DHWITHRFC2631KDF", BC_ESDH_OID);
    }

    private static final int TRIALS = 3;

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

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /** A fresh keypair on the ffdhe2048 named group. */
    private static KeyPair generate() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JSL);
        kpg.initialize(KEY_BITS);
        return kpg.generateKeyPair();
    }

    /** A second keypair on the SAME group as {@code peer}, so the two can agree. */
    private static KeyPair generateOn(DHParameterSpec params) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JSL);
        kpg.initialize(new DHParameterSpec(params.getP(), params.getG()));
        return kpg.generateKeyPair();
    }

    private static DHParameterSpec paramsOf(KeyPair pair)
    {
        return ((DHPublicKey) pair.getPublic()).getParams();
    }

    private static byte[] rawSecret(String provider, PrivateKey priv, PublicKey peer) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DH", provider);
        ka.init(priv);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }

    /** The RFC 2631 KEK the registered transformation derives. */
    private static byte[] rfc2631Kek(PrivateKey priv, PublicKey peer, byte[] ukm) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DHWITHRFC2631KDF", JSL);
        if (ukm == null)
        {
            ka.init(priv);
        }
        else
        {
            ka.init(priv, new UserKeyingMaterialSpec(ukm));
        }
        ka.doPhase(peer, true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    /** The KEK BouncyCastle's own JCE service derives, under the ESDH OID. */
    private static byte[] bcJceKek(PrivateKey priv, PublicKey peer, byte[] ukm) throws Exception
    {
        KeyFactory bcKf = KeyFactory.getInstance("DH", BC);
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
        PublicKey bcPeer = bcKf.generatePublic(new X509EncodedKeySpec(peer.getEncoded()));

        KeyAgreement ka = KeyAgreement.getInstance(BC_ESDH_OID, BC);
        if (ukm == null)
        {
            ka.init(bcPriv);
        }
        else
        {
            ka.init(bcPriv, new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        ka.doPhase(bcPeer, true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    /** BouncyCastle's lightweight RFC 2631 / X9.42 KEK over the same raw secret. */
    private static byte[] bcKekReference(byte[] zz, byte[] ukm, int kekBytes)
    {
        DHKEKGenerator gen = new DHKEKGenerator(new SHA1Digest());
        gen.init(new DHKDFParameters(new ASN1ObjectIdentifier(AES256_WRAP), kekBytes * 8, zz, ukm));
        byte[] out = new byte[kekBytes];
        gen.generateBytes(out, 0, out.length);
        return out;
    }

    // -----------------------------------------------------------------
    // Completeness guards
    // -----------------------------------------------------------------

    /**
     * Every DH service JSL registers is DRIVEN, discovered by SPI class-name
     * prefix, aliases included — which covers the {@code DiffieHellman} and OID
     * spellings.
     */
    @Test
    public void everyRegisteredDhServiceIsDriven() throws Exception
    {
        final SecureRandom sr = seededRandom("everyRegisteredDhServiceIsDriven");
        final KeyPair alice = generate();
        final KeyPair bob = generateOn(paramsOf(alice));

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.DH_PREFIX, "DH (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        if ("KeyAgreement".equals(type))
                        {
                            KeyAgreement ka = KeyAgreement.getInstance(alg, JSL);
                            ka.init(alice.getPrivate());
                            ka.doPhase(bob.getPublic(), true);
                            // The KDF variants require a target algorithm; the
                            // plain one does not accept a wrap OID.
                            byte[] out = isKdfAgreement(alg)
                                    ? ka.generateSecret(AES256_WRAP).getEncoded()
                                    : ka.generateSecret();
                            Assertions.assertTrue(out.length > 0,
                                    alg + ": derived an empty secret");
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new X509EncodedKeySpec(
                                            alice.getPublic().getEncoded()));
                            Assertions.assertTrue(Arrays.areEqual(
                                    alice.getPublic().getEncoded(), pub.getEncoded()), alg);
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            kpg.initialize(KEY_BITS);
                            KeyPair kp = kpg.generateKeyPair();
                            KeyPair peer = generateOn(paramsOf(kp));
                            Assertions.assertTrue(
                                    rawSecret(JSL, kp.getPrivate(), peer.getPublic()).length > 0,
                                    alg + ": generated a keypair that cannot agree");
                        }
                        else if ("AlgorithmParameters".equals(type))
                        {
                            AlgorithmParameters ap = AlgorithmParameters.getInstance(alg, JSL);
                            ap.init(paramsOf(alice));
                            Assertions.assertNotNull(ap.getEncoded(), alg);
                        }
                        else if ("AlgorithmParameterGenerator".equals(type))
                        {
                            AlgorithmParameterGenerator apg =
                                    AlgorithmParameterGenerator.getInstance(alg, JSL);
                            apg.init(PARAMGEN_BITS);
                            DHParameterSpec spec = apg.generateParameters()
                                    .getParameterSpec(DHParameterSpec.class);
                            Assertions.assertEquals(PARAMGEN_BITS, spec.getP().bitLength(),
                                    alg + ": generated p of the wrong size");
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
     * Whether a registered KeyAgreement name derives a KEK rather than the raw
     * secret, decided from the registrar's CLASS name rather than the
     * spelling — the alias spellings are where a substring test goes wrong, as
     * the EC and Ed sweeps both found.
     */
    private static boolean isKdfAgreement(String alg)
    {
        String cn = ProviderSurfaceGuard.registeredClassNames(Security.getProvider(JSL),
                        CipherFamilies.DH_PREFIX, GUARDED_TYPES)
                .get("KeyAgreement." + alg.toUpperCase(Locale.ROOT));
        Assertions.assertNotNull(cn, "no registered class for KeyAgreement." + alg);
        return cn.endsWith("DHWithKDFKeyAgreementSpi") || cn.contains("KDF");
    }

    /** The removal direction, at type granularity. */
    @Test
    public void everyGuardedTypeIsStillRegistered()
    {
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), CipherFamilies.DH_PREFIX, GUARDED_TYPES);

        SortedSet<String> missing = new TreeSet<String>();
        for (String type : GUARDED_TYPES)
        {
            boolean found = false;
            for (String entry : surface)
            {
                if (entry.startsWith(type + "."))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                missing.add(type);
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "JSL no longer registers any DH service of these types: " + missing);
    }

    /**
     * Every registered KeyAgreement name has a named reference: BC's JCE, or
     * BC's lightweight generator where BC has no JCE name for it.
     */
    @Test
    public void everyRegisteredKeyAgreementHasAReference()
    {
        SortedSet<String> covered = new TreeSet<String>(BC_JCE_KEY_AGREEMENT.keySet());

        Provider provider = Security.getProvider(JSL);
        SortedSet<String> registeredNames = new TreeSet<String>();
        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if ("KeyAgreement".equals(s.getType()) && cn != null
                    && cn.startsWith(CipherFamilies.DH_PREFIX))
            {
                registeredNames.add(s.getAlgorithm().toUpperCase(Locale.ROOT));
            }
        }
        Assertions.assertFalse(registeredNames.isEmpty(), "JSL registered no DH KeyAgreement services");

        SortedSet<String> uncovered = new TreeSet<String>(registeredNames);
        uncovered.removeAll(covered);
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSL registers DH KeyAgreement services with no reference in this class: " + uncovered);

        SortedSet<String> stale = new TreeSet<String>(covered);
        stale.removeAll(registeredNames);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names DH KeyAgreement services JSL does not register: " + stale);
    }

    // -----------------------------------------------------------------
    // KeyAgreement
    // -----------------------------------------------------------------

    /**
     * The raw DH shared secret is a deterministic function of the two keys, so
     * it must be byte-identical across providers. A different peer must produce
     * a different secret, so an implementation returning a constant cannot pass.
     */
    @Test
    public void plainDhSharedSecretAgreesWithBouncyCastle() throws Exception
    {
        seededRandom("plainDhSharedSecretAgreesWithBouncyCastle");

        for (int t = 0; t < TRIALS; t++)
        {
            KeyPair alice = generate();
            KeyPair bob = generateOn(paramsOf(alice));
            KeyPair mallory = generateOn(paramsOf(alice));

            KeyFactory bcKf = KeyFactory.getInstance("DH", BC);
            PrivateKey bcPriv = bcKf.generatePrivate(
                    new PKCS8EncodedKeySpec(alice.getPrivate().getEncoded()));
            PublicKey bcPeer = bcKf.generatePublic(
                    new X509EncodedKeySpec(bob.getPublic().getEncoded()));

            byte[] jslSecret = rawSecret(JSL, alice.getPrivate(), bob.getPublic());
            Assertions.assertArrayEquals(rawSecret(BC, bcPriv, bcPeer), jslSecret,
                    "DH shared secret differs from BC");

            Assertions.assertFalse(
                    Arrays.areEqual(jslSecret, rawSecret(JSL, alice.getPrivate(), mallory.getPublic())),
                    "a different peer produced the same shared secret");
        }
    }

    /**
     * {@code DHWITHRFC2631KDF} against BOTH of BouncyCastle's implementations —
     * its JCE service under the ESDH OID and its lightweight
     * {@code DHKEKGenerator} — with and without user keying material. A different UKM must derive a different KEK, so a KDF
     * that ignored it cannot pass.
     */
    @Test
    public void rfc2631KdfAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("rfc2631KdfAgreesWithBouncyCastle");

        for (int t = 0; t < TRIALS; t++)
        {
            KeyPair alice = generate();
            KeyPair bob = generateOn(paramsOf(alice));
            byte[] zz = rawSecret(JSL, alice.getPrivate(), bob.getPublic());

            for (int withUkm = 0; withUkm < 2; withUkm++)
            {
                byte[] ukm = null;
                if (withUkm == 1)
                {
                    ukm = new byte[8 + sr.nextInt(32)];
                    sr.nextBytes(ukm);
                }

                byte[] kek = rfc2631Kek(alice.getPrivate(), bob.getPublic(), ukm);

                // Primary reference: BC's own JCE service, under the ESDH OID.
                Assertions.assertArrayEquals(bcJceKek(alice.getPrivate(), bob.getPublic(), ukm), kek,
                        "DHWITHRFC2631KDF: derived KEK differs from BC's JCE (" + BC_ESDH_OID + ")");

                // Second, independent reference: the lightweight generator the
                // KDF recurrence itself is validated against elsewhere. Kept
                // because it exercises a different BC code path to the same
                // answer, not because the JCE name is missing.
                Assertions.assertArrayEquals(bcKekReference(zz, ukm, kek.length), kek,
                        "DHWITHRFC2631KDF: derived KEK differs from BC's DHKEKGenerator");
            }

            byte[] ukmA = new byte[16];
            byte[] ukmB = new byte[16];
            sr.nextBytes(ukmA);
            do
            {
                sr.nextBytes(ukmB);
            }
            while (Arrays.areEqual(ukmA, ukmB));

            Assertions.assertFalse(Arrays.areEqual(
                            rfc2631Kek(alice.getPrivate(), bob.getPublic(), ukmA),
                            rfc2631Kek(alice.getPrivate(), bob.getPublic(), ukmB)),
                    "a different UKM derived the same KEK");
        }
    }

    // -----------------------------------------------------------------
    // Keys and parameters
    // -----------------------------------------------------------------

    /**
     * A keypair generated by either provider must re-encode identically through
     * the other, on both halves, and still agree afterwards.
     */
    @Test
    public void keysRoundTripThroughBothKeyFactories() throws Exception
    {
        seededRandom("keysRoundTripThroughBothKeyFactories");

        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        KeyFactory bcKf = KeyFactory.getInstance("DH", BC);

        KeyPair jslPair = generate();
        Assertions.assertTrue(Arrays.areEqual(jslPair.getPublic().getEncoded(),
                        bcKf.generatePublic(new X509EncodedKeySpec(
                                jslPair.getPublic().getEncoded())).getEncoded()),
                "BC re-encoded a JSL public key differently");
        Assertions.assertTrue(Arrays.areEqual(jslPair.getPrivate().getEncoded(),
                        bcKf.generatePrivate(new PKCS8EncodedKeySpec(
                                jslPair.getPrivate().getEncoded())).getEncoded()),
                "BC re-encoded a JSL private key differently");

        DHParameterSpec params = paramsOf(jslPair);
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DH", BC);
        bcKpg.initialize(new DHParameterSpec(params.getP(), params.getG()));
        KeyPair bcPair = bcKpg.generateKeyPair();

        PublicKey viaJslPub = jslKf.generatePublic(
                new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
        PrivateKey viaJslPriv = jslKf.generatePrivate(
                new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
        Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(),
                        viaJslPub.getEncoded()),
                "JSL re-encoded a BC public key differently");
        Assertions.assertTrue(Arrays.areEqual(bcPair.getPrivate().getEncoded(),
                        viaJslPriv.getEncoded()),
                "JSL re-encoded a BC private key differently");

        // The round-tripped BC keypair still agrees with the JSL one.
        Assertions.assertArrayEquals(
                rawSecret(JSL, viaJslPriv, jslPair.getPublic()),
                rawSecret(JSL, jslPair.getPrivate(), viaJslPub),
                "a round-tripped BC keypair no longer agrees with the JSL one");
    }

    /**
     * The PKCS#3 {@code DHParameter} codec must agree with BC in both
     * directions.
     * <p>
     * <b>Deliberately the PKCS#3 form, built as a plain {@code
     * DHParameterSpec(p, g)}.</b> A spec taken from a JSL key is a {@code
     * DHDomainParameterSpec} and encodes the ANSI X9.42 {@code DomainParameters}
     * SEQUENCE {p, g, q} — measured 528 bytes against PKCS#3's 268 — because
     * JSL preserves the subgroup order the ffdhe2048 group carries. BC's {@code
     * DHParameterSpec} has no q field, so comparing those two encodings
     * byte-for-byte compares different STRUCTURES, not two implementations of
     * one. The q-preserving form's BC interop is {@link DHX942Test}'s subject
     * ({@code jslEncodesX942_bcDecodesAndAgrees} and its reverse) and is not
     * re-litigated here.
     */
    @Test
    public void algorithmParametersAgreeWithBouncyCastle() throws Exception
    {
        DHParameterSpec keyDerived = paramsOf(generate());
        DHParameterSpec domain = new DHParameterSpec(keyDerived.getP(), keyDerived.getG());

        AlgorithmParameters jslAp = AlgorithmParameters.getInstance("DH", JSL);
        jslAp.init(domain);
        AlgorithmParameters bcAp = AlgorithmParameters.getInstance("DH", BC);
        bcAp.init(domain);
        Assertions.assertArrayEquals(bcAp.getEncoded(), jslAp.getEncoded(),
                "JSL and BC encode the same DH parameters differently");

        assertSameDomain(domain, reread(BC, jslAp.getEncoded()), "BC reading a JSL encoding");
        assertSameDomain(domain, reread(JSL, bcAp.getEncoded()), "JSL reading a BC encoding");
    }

    /**
     * Generated parameters are a randomised safe-prime search, so agreement is
     * CROSS-ACCEPTANCE: BC must read them back unchanged and build a keypair on
     * them that agrees with a JSL keypair on the same group.
     * <p>
     * Runs at {@link #PARAMGEN_BITS} and ONCE — see that constant for the
     * measured cost that makes repetition unaffordable.
     */
    @Test
    public void generatedParametersAreAcceptedByBouncyCastle() throws Exception
    {
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DH", JSL);
        apg.init(PARAMGEN_BITS);
        AlgorithmParameters generated = apg.generateParameters();
        DHParameterSpec spec = generated.getParameterSpec(DHParameterSpec.class);
        Assertions.assertEquals(PARAMGEN_BITS, spec.getP().bitLength(),
                "JSL generated p of the wrong size");

        assertSameDomain(spec, reread(BC, generated.getEncoded()),
                "BC reading JSL-generated parameters");

        // Accepted means USABLE, not merely parsed: both providers build a
        // keypair on the group and the two agree.
        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("DH", JSL);
        jslKpg.initialize(new DHParameterSpec(spec.getP(), spec.getG()));
        KeyPair jslPair = jslKpg.generateKeyPair();

        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DH", BC);
        bcKpg.initialize(new DHParameterSpec(spec.getP(), spec.getG()));
        KeyPair bcPair = bcKpg.generateKeyPair();

        KeyFactory bcKf = KeyFactory.getInstance("DH", BC);
        PublicKey jslPubViaBc = bcKf.generatePublic(
                new X509EncodedKeySpec(jslPair.getPublic().getEncoded()));
        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        PublicKey bcPubViaJsl = jslKf.generatePublic(
                new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));

        Assertions.assertArrayEquals(
                rawSecret(BC, bcPair.getPrivate(), jslPubViaBc),
                rawSecret(JSL, jslPair.getPrivate(), bcPubViaJsl),
                "JSL-generated parameters did not yield an agreeing keypair across providers");
    }

    private static DHParameterSpec reread(String provider, byte[] encoded) throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("DH", provider);
        ap.init(encoded);
        return ap.getParameterSpec(DHParameterSpec.class);
    }

    private static void assertSameDomain(DHParameterSpec expected, DHParameterSpec actual, String what)
    {
        Assertions.assertEquals(expected.getP(), actual.getP(), what + ": p differs");
        Assertions.assertEquals(expected.getG(), actual.getG(), what + ": g differs");
    }
}
