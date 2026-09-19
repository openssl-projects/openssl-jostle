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

package org.openssl.jostle.test.slhdsa;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Cross-implementation agreement for the WHOLE base-provider ({@code JSL})
 * SLH-DSA surface, against BouncyCastle 1.86.
 * <p>
 * Non-FIPS counterpart of {@code FIPSSLHDSAAgreementTest}. Neither substitutes
 * for the other: they drive different native libraries and different lib ctxs,
 * and the FIPS half is gated on what the loaded module can fetch.
 * <p>
 * <b>Three reference surfaces, because Jostle registers three signature
 * behaviours and BouncyCastle exposes only one of them through the JCE.</b>
 * <ul>
 * <li>The twelve parameter-set names and the pure names are compared against
 * BC's JCE {@code SLH-DSA*} services.</li>
 * <li>{@code DET-SLH-DSA-PURE} has no BC JCE name. BC's JCE signer is itself
 * DETERMINISTIC, so the reference is that same service and the comparison is
 * BYTE EQUALITY.</li>
 * <li>{@code SLH-DSA-NONE} and {@code DET-SLH-DSA-NONE} sign with no message
 * encoding — no domain separator, no context octet — which BC exposes only as
 * the protected {@code internalGenerateSignature} /
 * {@code internalVerifySignature} on its lightweight
 * {@link org.bouncycastle.crypto.signers.SLHDSASigner}. {@link RawSlhDsaSigner}
 * reaches them. A BouncyCastle release that changes those members breaks this
 * file at COMPILE time, which is the right failure.</li>
 * </ul>
 * For the deterministic pair the expected {@code opt_rand} is the private key's
 * PK.seed: FIPS 205 Algorithm 19 line 2, "substitute opt_rand ← PK.seed for the
 * deterministic variant" (standards library FIPS-205.pdf, INDEX hash
 * 8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d).
 * <p>
 * <b>Reference provider.</b> Every BouncyCastle JCE object this class uses
 * asserts its own provider name before its result is believed. Without that, a
 * driver that resolved the reference back to JSL would compare Jostle with
 * itself and pass — and {@code assertEveryServiceDriven} catches Throwable per
 * entry, so it would pass silently.
 * <p>
 * Depth stays elsewhere: {@link SLHDSATest} keeps the parameter-spec contracts
 * and state-machine sequences, {@link SLHDSALimitTest} the NI rejections.
 * <p>
 * <b>Falsification (2026-09-19).</b> RED: dropping the
 * {@code SLH-DSA-SHAKE-256S} arm from {@link #bcSignatureName} failed
 * {@link #everyRegisteredSlhDsaServiceIsDriven} naming that Signature and its
 * OID alias, while {@code MLDSAAgreementTest}'s guard stayed green. RED:
 * replacing the BC verifier with a JSL verifier failed the reference-provider
 * assertion in the same cell. GREEN: restored, both green.
 * <p>
 * Inputs come from a per-test SHA1PRNG whose seed is logged. Keypairs are
 * generated once per parameter set because the slow variants cost seconds and
 * key generation is not what this class measures.
 */
public class SLHDSAAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** The three JCA types {@code ProvSLHDSA} registers under. */
    private static final String[] GUARDED_TYPES = {"KeyFactory", "KeyPairGenerator", "Signature"};

    /**
     * The parameter set every name that does not pin one is driven with. A
     * "128F" set is chosen deliberately: the "S" variants sign in seconds.
     */
    private static final String DEFAULT_SET = "SLH-DSA-SHA2-128F";

    /**
     * Two sets for the cells that do not need all twelve — one SHA2 and one
     * SHAKE, both fast — so the depth cells stay inside a sensible runtime
     * while still crossing both hash families.
     */
    private static final String[] FAST_SETS = {"SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F"};

    /**
     * NIST CSOR id-slh-dsa-*, RFC 9814, as the SubjectPublicKeyInfo must carry
     * them. Dotted literals are deliberate in tests; production uses the oids
     * constants.
     */
    private static final Map<String, String> SPKI_OID = new LinkedHashMap<String, String>();

    static
    {
        SPKI_OID.put("SLH-DSA-SHA2-128S", "2.16.840.1.101.3.4.3.20");
        SPKI_OID.put("SLH-DSA-SHA2-128F", "2.16.840.1.101.3.4.3.21");
        SPKI_OID.put("SLH-DSA-SHA2-192S", "2.16.840.1.101.3.4.3.22");
        SPKI_OID.put("SLH-DSA-SHA2-192F", "2.16.840.1.101.3.4.3.23");
        SPKI_OID.put("SLH-DSA-SHA2-256S", "2.16.840.1.101.3.4.3.24");
        SPKI_OID.put("SLH-DSA-SHA2-256F", "2.16.840.1.101.3.4.3.25");
        SPKI_OID.put("SLH-DSA-SHAKE-128S", "2.16.840.1.101.3.4.3.26");
        SPKI_OID.put("SLH-DSA-SHAKE-128F", "2.16.840.1.101.3.4.3.27");
        SPKI_OID.put("SLH-DSA-SHAKE-192S", "2.16.840.1.101.3.4.3.28");
        SPKI_OID.put("SLH-DSA-SHAKE-192F", "2.16.840.1.101.3.4.3.29");
        SPKI_OID.put("SLH-DSA-SHAKE-256S", "2.16.840.1.101.3.4.3.30");
        SPKI_OID.put("SLH-DSA-SHAKE-256F", "2.16.840.1.101.3.4.3.31");
    }

    /** Low deliberately: the twelve sets include six "S" variants that sign in seconds. */
    private static final int TRIALS = 3;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** One keypair per parameter set, shared across cells; keygen is not the subject. */
    private static final Map<String, KeyPair> KEY_PAIRS = new HashMap<String, KeyPair>();

    /**
     * BouncyCastle's raw (no message-encoding) SLH-DSA, which 1.86 exposes only
     * as protected members. The only independent witness for
     * {@code SLH-DSA-NONE} and {@code DET-SLH-DSA-NONE}.
     */
    static final class RawSlhDsaSigner extends SLHDSASigner
    {
        /** {@code optRand} null means BC's own hedged draw; PK.seed means deterministic. */
        byte[] signRaw(byte[] message, byte[] optRand)
        {
            return internalGenerateSignature(message, optRand);
        }

        boolean verifyRaw(byte[] message, byte[] signature)
        {
            return internalVerifySignature(message, signature);
        }
    }

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

    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    private static synchronized KeyPair keyPair(String paramSet) throws Exception
    {
        KeyPair kp = KEY_PAIRS.get(paramSet);
        if (kp == null)
        {
            kp = KeyPairGenerator.getInstance(paramSet, JSL).generateKeyPair();
            KEY_PAIRS.put(paramSet, kp);
        }
        return kp;
    }

    /** A BouncyCastle Signature under {@code alg}, with its provider asserted. */
    private static Signature bcSignature(String alg) throws Exception
    {
        Signature s = Signature.getInstance(alg, BC);
        Assertions.assertEquals(BC, s.getProvider().getName(),
                "the reference signature for " + alg + " did not come from BouncyCastle");
        return s;
    }

    /** A BouncyCastle KeyFactory, with its provider asserted. */
    private static KeyFactory bcKeyFactory(String alg) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(alg, BC);
        Assertions.assertEquals(BC, kf.getProvider().getName(),
                "the reference key factory for " + alg + " did not come from BouncyCastle");
        return kf;
    }

    /**
     * The name a registered JSL service resolves to in the registrar's own
     * alias table. Resolving the alias first is what stops the driver guessing
     * a parameter set from an OID, whose last arc is the only thing that
     * distinguishes SHA2-256S from SHAKE-256F.
     */
    private static String primaryOf(String type, String alg)
    {
        Provider provider = Security.getProvider(JSL);
        String primary = provider.getProperty("Alg.Alias." + type + "." + alg);
        return (primary == null ? alg : primary).toUpperCase(Locale.ROOT);
    }

    /** The parameter set a registered name operates on, resolved through the primary. */
    private static String paramSetOf(String type, String alg)
    {
        String primary = primaryOf(type, alg);
        if (SPKI_OID.containsKey(primary))
        {
            return primary;
        }
        return DEFAULT_SET;
    }

    /**
     * BouncyCastle's JCE spelling for one of our registered Signature names,
     * or null where BC has no JCE service and the lightweight signer is the
     * reference.
     * <p>
     * Measured on bcprov 1.86: BC serves {@code SLH-DSA} and the twelve
     * parameter-set names, and nothing for the message-encoding variants.
     * THROWS on an unknown name, so a newly registered variant fails the
     * completeness guard rather than going unexercised.
     */
    private static String bcSignatureName(String type, String alg)
    {
        String primary = primaryOf(type, alg);
        if (SPKI_OID.containsKey(primary))
        {
            return primary;
        }
        if ("SLHDSA".equals(primary) || "SLH-DSA-PURE".equals(primary))
        {
            return "SLH-DSA";
        }
        if (NO_BC_JCE_NAME.contains(primary))
        {
            return null;
        }
        throw new IllegalStateException("no BouncyCastle reference defined for Signature." + alg
                + " (primary " + primary + ") — teach bcSignatureName rather than leaving it unexercised");
    }

    /**
     * The registered Signature names BouncyCastle does NOT expose through the
     * JCE. Compared against its lightweight signer instead of being skipped,
     * and named so the completeness guard reads them as a decision, not a gap.
     */
    private static final SortedSet<String> NO_BC_JCE_NAME =
            Collections.unmodifiableSortedSet(new TreeSet<String>(java.util.Arrays.asList(
                    "SLH-DSA-NONE", "DET-SLH-DSA-PURE", "DET-SLH-DSA-NONE")));

    private static byte[] sign(String alg, PrivateKey key, byte[] msg) throws Exception
    {
        Signature s = Signature.getInstance(alg, JSL);
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String alg, PublicKey key, byte[] msg, byte[] sig) throws Exception
    {
        Signature s = Signature.getInstance(alg, JSL);
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    private static byte[] bcSign(String alg, PrivateKey key, byte[] msg) throws Exception
    {
        Signature s = bcSignature(alg);
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean bcVerify(String alg, PublicKey key, byte[] msg, byte[] sig) throws Exception
    {
        Signature s = bcSignature(alg);
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    private static PublicKey bcPublic(PublicKey jslKey) throws Exception
    {
        return bcKeyFactory("SLH-DSA").generatePublic(new X509EncodedKeySpec(jslKey.getEncoded()));
    }

    private static PrivateKey bcPrivate(PrivateKey jslKey) throws Exception
    {
        return bcKeyFactory("SLH-DSA").generatePrivate(new PKCS8EncodedKeySpec(jslKey.getEncoded()));
    }

    /** BC's lightweight private key parameters for a JSL private key. */
    private static SLHDSAPrivateKeyParameters lightweightPrivate(PrivateKey key) throws Exception
    {
        return (SLHDSAPrivateKeyParameters) PrivateKeyFactory.createKey(key.getEncoded());
    }

    private static AsymmetricKeyParameter lightweightPublic(PublicKey key) throws Exception
    {
        return PublicKeyFactory.createKey(key.getEncoded());
    }

    // -----------------------------------------------------------------
    // Completeness guards
    // -----------------------------------------------------------------

    /**
     * Every SLH-DSA service JSL registers is DRIVEN against BouncyCastle,
     * discovered by SPI class-name prefix, aliases included — which is what
     * covers the twelve CSOR OID spellings and the unhyphenated
     * {@code SLHDSA}.
     */
    @Test
    public void everyRegisteredSlhDsaServiceIsDriven() throws Exception
    {
        final SecureRandom sr = seededRandom("everyRegisteredSlhDsaServiceIsDriven");

        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                CipherFamilies.SLHDSA_PREFIX, "SLH-DSA (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        String set = paramSetOf(type, alg);
                        KeyPair kp = keyPair(set);
                        byte[] msg = new byte[1 + sr.nextInt(256)];
                        sr.nextBytes(msg);

                        if ("Signature".equals(type))
                        {
                            driveSignature(type, alg, kp, msg);
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            PublicKey pub = KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                            Assertions.assertTrue(
                                    Arrays.areEqual(kp.getPublic().getEncoded(), pub.getEncoded()),
                                    alg + ": re-encoded a public key differently");
                            PrivateKey priv = KeyFactory.getInstance(alg, JSL)
                                    .generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
                            byte[] sig = sign(set, priv, msg);
                            Assertions.assertTrue(bcVerify(set, bcPublic(pub), msg, sig),
                                    alg + ": BouncyCastle rejected a signature from the crossed key");
                        }
                        else if ("KeyPairGenerator".equals(type))
                        {
                            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
                            // The bare names carry no set; pin one so the driver
                            // does not depend on an SPI default.
                            if (!SPKI_OID.containsKey(primaryOf(type, alg)))
                            {
                                kpg.initialize(SLHDSAParameterSpec.fromName(set));
                            }
                            KeyPair generated = kpg.generateKeyPair();
                            byte[] sig = sign(set, generated.getPrivate(), msg);
                            Assertions.assertTrue(
                                    bcVerify(set, bcPublic(generated.getPublic()), msg, sig),
                                    alg + ": BouncyCastle rejected a signature from a generated keypair");
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
     * One Signature name, driven against BouncyCastle — its JCE service where
     * there is one, its lightweight raw signer where there is not.
     */
    private static void driveSignature(String type, String alg, KeyPair kp, byte[] msg)
            throws Exception
    {
        String bcAlg = bcSignatureName(type, alg);
        if (bcAlg != null)
        {
            byte[] sig = sign(alg, kp.getPrivate(), msg);
            Assertions.assertTrue(bcVerify(bcAlg, bcPublic(kp.getPublic()), msg, sig),
                    alg + ": BouncyCastle rejected a JSL signature");
            byte[] bcSig = bcSign(bcAlg, bcPrivate(kp.getPrivate()), msg);
            Assertions.assertTrue(verify(alg, kp.getPublic(), msg, bcSig),
                    alg + ": JSL rejected a BouncyCastle signature");
            return;
        }

        // No BC JCE name: the raw signer is the reference.
        byte[] sig = sign(alg, kp.getPrivate(), msg);
        if (primaryOf(type, alg).endsWith("-NONE"))
        {
            RawSlhDsaSigner raw = new RawSlhDsaSigner();
            raw.init(false, lightweightPublic(kp.getPublic()));
            Assertions.assertTrue(raw.verifyRaw(msg, sig),
                    alg + ": BouncyCastle's raw verifier rejected a JSL signature");
            return;
        }
        // DET-SLH-DSA-PURE: BC's own JCE signer is deterministic, so the
        // reference is byte equality against it.
        Assertions.assertArrayEquals(bcSign("SLH-DSA", bcPrivate(kp.getPrivate()), msg), sig,
                alg + ": the deterministic signature differs from BouncyCastle's");
    }

    /** The removal direction, at type granularity. */
    @Test
    public void everyGuardedTypeIsStillRegistered()
    {
        SortedSet<String> surface = ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), CipherFamilies.SLHDSA_PREFIX, GUARDED_TYPES);

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
                "JSL no longer registers any SLH-DSA service of these types: " + missing);
    }

    /**
     * Every registered Signature name has a named reference — BC's JCE where it
     * has one, the lightweight raw signer where it does not — and every name
     * this class claims to cover is still registered.
     */
    @Test
    public void everyRegisteredSignatureHasAReference()
    {
        SortedSet<String> registered = new TreeSet<String>();
        for (String alg : registered("Signature"))
        {
            registered.add(alg.toUpperCase(Locale.ROOT));
        }

        SortedSet<String> unreferenced = new TreeSet<String>();
        for (String alg : registered)
        {
            try
            {
                bcSignatureName("Signature", alg);
            }
            catch (IllegalStateException e)
            {
                unreferenced.add(alg);
            }
        }
        Assertions.assertTrue(unreferenced.isEmpty(),
                "JSL registers SLH-DSA Signature services with no reference in this class: "
                        + unreferenced);

        SortedSet<String> stale = new TreeSet<String>(NO_BC_JCE_NAME);
        stale.removeAll(registered);
        Assertions.assertTrue(stale.isEmpty(),
                "this class names SLH-DSA Signature services JSL does not register: " + stale);
    }

    /** Every SLH-DSA primary of one type that {@code ProvSLHDSA} registers, sorted. */
    private static List<String> registered(String type)
    {
        Provider provider = Security.getProvider(JSL);
        Assertions.assertNotNull(provider, "JSL provider is not registered");

        List<String> names = new ArrayList<String>();
        for (Provider.Service s : provider.getServices())
        {
            String cn = s.getClassName();
            if (type.equals(s.getType()) && cn != null && cn.startsWith(CipherFamilies.SLHDSA_PREFIX))
            {
                names.add(s.getAlgorithm());
            }
        }
        Assertions.assertFalse(names.isEmpty(), "JSL registered no SLH-DSA " + type + " services");
        Collections.sort(names);
        return names;
    }

    // -----------------------------------------------------------------
    // Signature agreement
    // -----------------------------------------------------------------

    /**
     * Every one of the twelve parameter sets, both directions, with the
     * differentiators a cross-verification needs: a tampered message, a
     * tampered signature and a foreign key.
     */
    @Test
    public void signaturesCrossVerifyWithBouncyCastleBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("signaturesCrossVerifyWithBouncyCastleBothDirections");

        for (String set : SPKI_OID.keySet())
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());

            byte[] msg = new byte[1 + sr.nextInt(1024)];
            sr.nextBytes(msg);

            byte[] jslSig = sign(set, kp.getPrivate(), msg);
            Assertions.assertTrue(bcVerify(set, bcPub, msg, jslSig),
                    set + ": BouncyCastle rejected a JSL signature");

            byte[] bcSig = bcSign(set, bcPriv, msg);
            Assertions.assertTrue(verify(set, kp.getPublic(), msg, bcSig),
                    set + ": JSL rejected a BouncyCastle signature");

            byte[] tampered = Arrays.clone(msg);
            tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify(set, kp.getPublic(), tampered, bcSig),
                    set + ": JSL accepted a signature over a tampered message");
            Assertions.assertFalse(bcVerify(set, bcPub, tampered, jslSig),
                    set + ": BouncyCastle accepted a signature over a tampered message");

            byte[] mangled = Arrays.clone(jslSig);
            mangled[sr.nextInt(mangled.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(bcVerify(set, bcPub, msg, mangled),
                    set + ": BouncyCastle accepted a tampered signature");
        }

        // A key from a DIFFERENT pair must not verify. One fast set is enough:
        // the check is of the verifier, not of the parameter set.
        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            KeyPair other = KeyPairGenerator.getInstance(set, JSL).generateKeyPair();
            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(set, kp.getPrivate(), msg);
            Assertions.assertFalse(bcVerify(set, bcPublic(other.getPublic()), msg, sig),
                    set + ": BouncyCastle accepted a signature under the wrong public key");
        }
    }

    /**
     * {@code DET-SLH-DSA-PURE} is byte-equal to BouncyCastle's JCE signer and
     * {@code SLH-DSA-PURE} is not, so the hedged and deterministic
     * registrations are proven distinct.
     * <p>
     * Byte equality is what cross-verification cannot give here: a deviation in
     * the randomiser R still produces a signature that verifies, and R is the
     * deterministic variant's whole content. Both directions are driven.
     */
    @Test
    public void theDeterministicVariantIsByteEqualToBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("theDeterministicVariantIsByteEqualToBouncyCastle");

        for (String set : SPKI_OID.keySet())
        {
            KeyPair kp = keyPair(set);
            PrivateKey bcPriv = bcPrivate(kp.getPrivate());
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[1 + sr.nextInt(512)];
            sr.nextBytes(msg);

            byte[] det = sign("DET-SLH-DSA-PURE", kp.getPrivate(), msg);
            Assertions.assertArrayEquals(bcSign("SLH-DSA", bcPriv, msg), det,
                    set + ": the deterministic signature differs from BouncyCastle's");
            Assertions.assertArrayEquals(det, sign("DET-SLH-DSA-PURE", kp.getPrivate(), msg),
                    set + ": DET-SLH-DSA-PURE is not deterministic");
            Assertions.assertTrue(bcVerify(set, bcPub, msg, det),
                    set + ": BouncyCastle rejected the deterministic signature");

            // The hedged sibling must NOT be byte-equal, or the two
            // registrations differ in name only.
            Assertions.assertFalse(Arrays.areEqual(det, sign("SLH-DSA-PURE", kp.getPrivate(), msg)),
                    set + ": SLH-DSA-PURE produced the deterministic signature — "
                            + "the hedged and deterministic registrations are not distinct");

            // The other direction: BouncyCastle signs, both pure names verify.
            byte[] bcSig = bcSign("SLH-DSA", bcPriv, msg);
            Assertions.assertTrue(verify("DET-SLH-DSA-PURE", kp.getPublic(), msg, bcSig),
                    set + ": DET-SLH-DSA-PURE rejected a BouncyCastle signature");
            Assertions.assertTrue(verify("SLH-DSA-PURE", kp.getPublic(), msg, bcSig),
                    set + ": SLH-DSA-PURE rejected a BouncyCastle signature");
            byte[] tamperedMsg = Arrays.clone(msg);
            tamperedMsg[sr.nextInt(tamperedMsg.length)] ^= (byte) (1 + sr.nextInt(255));
            Assertions.assertFalse(verify("SLH-DSA-PURE", kp.getPublic(), tamperedMsg, bcSig),
                    set + ": SLH-DSA-PURE accepted a BouncyCastle signature over a tampered message");
        }
    }

    /**
     * The two {@code -NONE} names sign with no message encoding, which is the
     * form BouncyCastle keeps behind protected members.
     * <p>
     * {@code DET-SLH-DSA-NONE} is compared BYTE FOR BYTE against BC's raw
     * signer driven with {@code opt_rand} = PK.seed — FIPS 205 Algorithm 19
     * line 2. {@code SLH-DSA-NONE} is hedged, so it is cross-verified instead.
     * Both directions are driven. A {@code -NONE} signature must NOT satisfy
     * BC's JCE verifier, which applies the pure message encoding.
     */
    @Test
    public void theNoEncodingVariantsAgreeWithBouncyCastlesRawSigner() throws Exception
    {
        SecureRandom sr = seededRandom("theNoEncodingVariantsAgreeWithBouncyCastlesRawSigner");

        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            SLHDSAPrivateKeyParameters bcPriv = lightweightPrivate(kp.getPrivate());
            AsymmetricKeyParameter bcPub = lightweightPublic(kp.getPublic());

            for (int t = 0; t < TRIALS; t++)
            {
                byte[] msg = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(msg);

                byte[] hedged = sign("SLH-DSA-NONE", kp.getPrivate(), msg);
                RawSlhDsaSigner rawVerify = new RawSlhDsaSigner();
                rawVerify.init(false, bcPub);
                Assertions.assertTrue(rawVerify.verifyRaw(msg, hedged),
                        set + ": BouncyCastle's raw verifier rejected SLH-DSA-NONE");
                Assertions.assertFalse(Arrays.areEqual(hedged, sign("SLH-DSA-NONE", kp.getPrivate(), msg)),
                        set + ": SLH-DSA-NONE is deterministic — it should be hedged");

                byte[] det = sign("DET-SLH-DSA-NONE", kp.getPrivate(), msg);
                RawSlhDsaSigner rawSign = new RawSlhDsaSigner();
                rawSign.init(true, bcPriv);
                Assertions.assertArrayEquals(rawSign.signRaw(msg, bcPriv.getPublicSeed()), det,
                        set + ": DET-SLH-DSA-NONE differs from BouncyCastle's raw deterministic form");
                Assertions.assertArrayEquals(det, sign("DET-SLH-DSA-NONE", kp.getPrivate(), msg),
                        set + ": DET-SLH-DSA-NONE is not deterministic");

                // The message encoding is load-bearing: BC's JCE verifier
                // applies it, so a no-encoding signature must NOT satisfy it.
                Assertions.assertFalse(bcVerify(set, bcPublic(kp.getPublic()), msg, det),
                        set + ": BouncyCastle's pure verifier accepted a no-encoding signature — "
                                + "the message encoding is being ignored on one side");

                // The other direction. Verification does not consult the
                // randomiser, so BC's HEDGED raw signature verifies under both.
                // optRand is REQUIRED here: BC's raw signer dereferences it,
                // and FIPS 205 Algorithm 19 wants n bytes for the hedged form.
                byte[] optRand = new byte[bcPriv.getPublicSeed().length];
                sr.nextBytes(optRand);
                RawSlhDsaSigner rawHedged = new RawSlhDsaSigner();
                rawHedged.init(true, bcPriv);
                byte[] bcRaw = rawHedged.signRaw(msg, optRand);
                Assertions.assertTrue(verify("SLH-DSA-NONE", kp.getPublic(), msg, bcRaw),
                        set + ": SLH-DSA-NONE rejected a BouncyCastle raw signature");
                Assertions.assertTrue(verify("DET-SLH-DSA-NONE", kp.getPublic(), msg, bcRaw),
                        set + ": DET-SLH-DSA-NONE rejected a BouncyCastle raw signature");

                byte[] tampered = Arrays.clone(msg);
                tampered[sr.nextInt(tampered.length)] ^= (byte) (1 + sr.nextInt(255));
                RawSlhDsaSigner rawTampered = new RawSlhDsaSigner();
                rawTampered.init(false, bcPub);
                Assertions.assertFalse(rawTampered.verifyRaw(tampered, det),
                        set + ": BouncyCastle's raw verifier accepted a tampered message");
                Assertions.assertFalse(verify("SLH-DSA-NONE", kp.getPublic(), tampered, bcRaw),
                        set + ": SLH-DSA-NONE accepted a signature over a tampered message");
            }
        }
    }

    /**
     * The same message split several ways produces a signature BouncyCastle
     * verifies. Chunking is a dimension of the {@code update} contract that the
     * per-name completeness guard cannot see, and the independent verifier is
     * the point — a buffering fault shared by our signer and verifier passes a
     * self-check.
     */
    @Test
    public void chunkedUpdatesProduceSignaturesBouncyCastleVerifies() throws Exception
    {
        SecureRandom sr = seededRandom("chunkedUpdatesProduceSignaturesBouncyCastleVerifies");

        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            PublicKey bcPub = bcPublic(kp.getPublic());
            byte[] msg = new byte[1 + sr.nextInt(600)];
            sr.nextBytes(msg);

            for (int step : new int[]{0, 1, 31, 32, 33, 64})
            {
                Signature s = Signature.getInstance(set, JSL);
                s.initSign(kp.getPrivate());
                if (step == 0)
                {
                    s.update(msg);
                }
                else
                {
                    for (int off = 0; off < msg.length; off += step)
                    {
                        s.update(msg, off, Math.min(step, msg.length - off));
                    }
                }
                Assertions.assertTrue(bcVerify(set, bcPub, msg, s.sign()),
                        set + ": BouncyCastle rejected a signature built from " + step + "-byte chunks");
            }

            for (int t = 0; t < TRIALS; t++)
            {
                Signature s = Signature.getInstance(set, JSL);
                s.initSign(kp.getPrivate());
                int off = 0;
                while (off < msg.length)
                {
                    int n = 1 + sr.nextInt(msg.length - off);
                    s.update(msg, off, n);
                    off += n;
                }
                Assertions.assertTrue(bcVerify(set, bcPub, msg, s.sign()),
                        set + ": BouncyCastle rejected a signature built from random splits");
            }
        }
    }

    // -----------------------------------------------------------------
    // Key encodings
    // -----------------------------------------------------------------

    /**
     * An SLH-DSA keypair round-trips through BouncyCastle byte for byte, on
     * both halves and in both directions, for every parameter set, and still
     * operates.
     * <p>
     * SLH-DSA has no seed form to diverge over — the private key IS its four
     * seeds — so unlike ML-DSA both directions are byte-comparable here.
     */
    @Test
    public void keysRoundTripThroughBothKeyFactories() throws Exception
    {
        SecureRandom sr = seededRandom("keysRoundTripThroughBothKeyFactories");

        for (String set : SPKI_OID.keySet())
        {
            KeyPair jslPair = keyPair(set);
            Assertions.assertTrue(Arrays.areEqual(jslPair.getPublic().getEncoded(),
                            bcPublic(jslPair.getPublic()).getEncoded()),
                    set + ": BouncyCastle re-encoded a JSL public key differently");
            Assertions.assertTrue(Arrays.areEqual(jslPair.getPrivate().getEncoded(),
                            bcPrivate(jslPair.getPrivate()).getEncoded()),
                    set + ": BouncyCastle re-encoded a JSL private key differently");
        }

        for (String set : FAST_SETS)
        {
            KeyFactory jslKf = KeyFactory.getInstance(set, JSL);
            KeyPair bcPair = KeyPairGenerator.getInstance(set, BC).generateKeyPair();
            PublicKey viaJslPub = jslKf.generatePublic(
                    new X509EncodedKeySpec(bcPair.getPublic().getEncoded()));
            PrivateKey viaJslPriv = jslKf.generatePrivate(
                    new PKCS8EncodedKeySpec(bcPair.getPrivate().getEncoded()));
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPublic().getEncoded(),
                            viaJslPub.getEncoded()),
                    set + ": JSL re-encoded a BouncyCastle public key differently");
            Assertions.assertTrue(Arrays.areEqual(bcPair.getPrivate().getEncoded(),
                            viaJslPriv.getEncoded()),
                    set + ": JSL re-encoded a BouncyCastle private key differently");

            byte[] msg = new byte[64];
            sr.nextBytes(msg);
            byte[] sig = sign(set, viaJslPriv, msg);
            Signature bcCheck = bcSignature(set);
            bcCheck.initVerify(bcPair.getPublic());
            bcCheck.update(msg);
            Assertions.assertTrue(bcCheck.verify(sig),
                    set + ": a round-tripped BouncyCastle keypair no longer matches its own public key");
        }
    }

    /**
     * The SubjectPublicKeyInfo carries the CSOR OID for the parameter set, with
     * absent parameters — the fact a relying party keys off — and the OID alias
     * resolves to a Signature that BouncyCastle then verifies.
     */
    @Test
    public void subjectPublicKeyInfoCarriesTheRegisteredOid() throws Exception
    {
        SecureRandom sr = seededRandom("subjectPublicKeyInfoCarriesTheRegisteredOid");

        for (Map.Entry<String, String> e : SPKI_OID.entrySet())
        {
            KeyPair kp = keyPair(e.getKey());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            Assertions.assertEquals(e.getValue(), spki.getAlgorithm().getAlgorithm().getId(),
                    e.getKey() + ": wrong SubjectPublicKeyInfo algorithm OID");
            Assertions.assertNull(spki.getAlgorithm().getParameters(),
                    e.getKey() + ": the SLH-DSA AlgorithmIdentifier must carry absent parameters");
        }

        // One fast set proves the alias resolves; signing under all twelve OIDs
        // is what the completeness guard already does.
        for (String set : FAST_SETS)
        {
            KeyPair kp = keyPair(set);
            byte[] msg = new byte[48];
            sr.nextBytes(msg);
            byte[] sig = sign(SPKI_OID.get(set), kp.getPrivate(), msg);
            Assertions.assertTrue(bcVerify(set, bcPublic(kp.getPublic()), msg, sig),
                    set + ": a signature made under the OID alias did not verify at BouncyCastle");
        }
    }
}
