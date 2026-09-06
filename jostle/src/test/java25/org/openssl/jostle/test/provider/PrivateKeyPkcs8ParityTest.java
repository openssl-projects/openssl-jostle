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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPrivateKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMPrivateKeySpec;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHPrivateKeySpec;

/**
 * Item 1: for every KeyPairGenerator family JSL and BC share, the same PRIVATE
 * key built on both sides from shared material must encode to byte-identical
 * PKCS#8, or the divergence is pinned by name with its ASN.1 reason.
 *
 * <p>Material is shared, never an encoding: a decoder that returned its input
 * would satisfy a decode-and-re-encode round trip while agreeing about nothing.
 * The pins do parse, but only to name a divergence the byte comparison already
 * found.
 *
 * <p>In {@code src/test/java25} because {@code EdECPrivateKeySpec} is Java 15
 * and {@code XECPrivateKeySpec} Java 11, while {@code src/test/java} compiles
 * at release 8.
 *
 * <h2>Three disjoint states, measured 2026-09-06 against BC 1.85.2</h2>
 *
 * <p>9 cells, 3 pinned, 14 blocked, 26 shared. A family in none of the three,
 * or in two, fails {@link #everySharedFamilyIsAccountedFor}. RSA additionally
 * carries a pin for its CRT-less spec and the six PQ cells carry the seed-form
 * pin; those are annotations on cell families, not a fourth state.
 *
 * <h2>ML-DSA / ML-KEM private-key form</h2>
 *
 * <p>RFC 9881 section 6 and RFC 9935 section 6 define the CHOICE and give the
 * tags: {@code seed [0]} 0x80, {@code expandedKey} 0x04, {@code both} 0x30.
 * Uniform across all six families:
 *
 * <pre>
 * input form      ours          theirs        equal  note
 * seed spec       seed [0]      both          NO     ours is the RECOMMENDED form (9881/9935 s6)
 * expanded spec   expandedKey   expandedKey   YES    cell
 * own generated   both          both          same   9881 s8.1 recommends retaining the seed
 * ML-DSA seed     32 bytes      32 bytes      -      54-byte PKCS#8 ours
 * ML-KEM seed     64 bytes      64 bytes      -      86-byte PKCS#8 ours
 * cross-check     ours-generated == theirs-from-that-seed, all six
 * </pre>
 *
 * <p>The last row is an expansion-agreement witness, not a cell: the seed comes
 * out of jostle's generated key. The reverse cannot be built, since a seed spec
 * on jostle's side never yields the both arm.
 *
 * <p>Specifications quoted from the local standards library, INDEX.md sha256
 * 7c1604f5f5821fa3f85b5500e807c64fa14eb1c39bff4d659c5e9065bf439371.
 */
public class PrivateKeyPkcs8ParityTest
{
    private static Provider jsl;
    private static Provider bc;

    /** Byte-identical PKCS#8 from shared material. */
    private static final TreeSet<String> CELLS = new TreeSet<String>(java.util.Arrays.asList(
            "RSA", "DSA", "DH",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"));

    /** Divergent by design; each has a pin asserting both halves. */
    private static final TreeSet<String> PINNED = new TreeSet<String>(java.util.Arrays.asList(
            "EC", "ED25519", "ED448"));

    /** No shared material exists; each block guard asserts its reason live. */
    private static final TreeMap<String, String> BLOCKED = new TreeMap<String, String>();

    /** Both providers serve all four (measured). */
    private static final String[] EC_CURVES = {"secp256r1", "secp384r1", "secp521r1", "secp256k1"};

    static
    {
        BLOCKED.put("X25519", "BC 1.85.2 rejects the JDK XECPrivateKeySpec");
        BLOCKED.put("X448", "BC 1.85.2 rejects the JDK XECPrivateKeySpec");
        for (String h : new String[]{"SHA2", "SHAKE"})
        {
            for (String s : new String[]{"128", "192", "256"})
            {
                for (String v : new String[]{"S", "F"})
                {
                    BLOCKED.put("SLH-DSA-" + h + "-" + s + v, "BC ships no SLHDSAPrivateKeySpec");
                }
            }
        }
    }

    @BeforeAll
    public static void setUp()
    {
        jsl = new JostleProvider();
        bc = new BouncyCastleProvider();
        java.security.Security.addProvider(jsl);
        java.security.Security.addProvider(bc);
    }

    // ---- the completeness guard -----------------------------------------

    private static TreeSet<String> kpgNames(Provider p)
    {
        TreeSet<String> n = new TreeSet<String>();
        for (Provider.Service s : p.getServices())
        {
            if ("KeyPairGenerator".equals(s.getType()))
            {
                n.add(s.getAlgorithm());
            }
        }
        return n;
    }

    private static TreeSet<String> shared()
    {
        TreeSet<String> s = kpgNames(jsl);
        s.retainAll(kpgNames(bc));
        return s;
    }

    /**
     * Read from the live providers. Every shared family sits in exactly one
     * state, no entry names an unshared family, and the tally matches — so a
     * newly shared family arrives as a failure and a dead entry cannot hide a
     * lost one.
     */
    @Test
    public void everySharedFamilyIsAccountedFor()
    {
        TreeSet<String> shared = shared();
        Assertions.assertFalse(shared.isEmpty(), "vacuity: no shared KeyPairGenerator families");

        List<String> unaccounted = new ArrayList<String>();
        List<String> doubled = new ArrayList<String>();
        for (String f : shared)
        {
            int states = (CELLS.contains(f) ? 1 : 0) + (PINNED.contains(f) ? 1 : 0)
                    + (BLOCKED.containsKey(f) ? 1 : 0);
            if (states == 0)
            {
                unaccounted.add(f);
            }
            if (states > 1)
            {
                doubled.add(f);
            }
        }
        Assertions.assertTrue(unaccounted.isEmpty(),
                "shared families in no state — add a cell, a pin or a named block:\n  "
                        + String.join("\n  ", unaccounted));
        Assertions.assertTrue(doubled.isEmpty(),
                "the three states must be disjoint — a pinned family is not a cell:\n  "
                        + String.join("\n  ", doubled));

        List<String> stale = new ArrayList<String>();
        for (String f : CELLS)
        {
            if (!shared.contains(f))
            {
                stale.add("CELL " + f);
            }
        }
        for (String f : PINNED)
        {
            if (!shared.contains(f))
            {
                stale.add("PINNED " + f);
            }
        }
        for (String f : BLOCKED.keySet())
        {
            if (!shared.contains(f))
            {
                stale.add("BLOCKED " + f);
            }
        }
        Assertions.assertTrue(stale.isEmpty(), "entries naming unshared families: " + stale);

        Assertions.assertEquals(shared.size(), CELLS.size() + PINNED.size() + BLOCKED.size(),
                "tally must equal the shared set: " + shared.size() + " shared, "
                        + CELLS.size() + " cells + " + PINNED.size() + " pinned + "
                        + BLOCKED.size() + " blocked");
    }

    // ---- shared helpers --------------------------------------------------

    private static byte[] encode(Provider p, String alg, KeySpec spec) throws Exception
    {
        PrivateKey k = KeyFactory.getInstance(alg, p).generatePrivate(spec);
        byte[] e = k.getEncoded();
        Assertions.assertNotNull(e, alg + ": " + p.getName() + " produced no encoding");
        Assertions.assertTrue(e.length > 0, alg + ": " + p.getName() + " produced an empty encoding");
        return e;
    }

    /** A cell: identical material in, identical PKCS#8 out, no decoder between. */
    private static void assertCell(String label, String alg, KeySpec jslSpec, KeySpec bcSpec)
            throws Exception
    {
        byte[] ours = encode(jsl, alg, jslSpec);
        byte[] theirs = encode(bc, alg, bcSpec);
        Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                label + ": PKCS#8 differs — jsl " + ours.length + "B, bc " + theirs.length + "B");
    }

    private static ECParameterSpec namedParams(Provider p, String curve) throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", p);
        ap.init(new ECGenParameterSpec(curve));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] algIdOf(byte[] pkcs8) throws Exception
    {
        return PrivateKeyInfo.getInstance(pkcs8).getPrivateKeyAlgorithm()
                .toASN1Primitive().getEncoded("DER");
    }

    private static byte[] privateKeyOctetsOf(byte[] pkcs8) throws Exception
    {
        return PrivateKeyInfo.getInstance(pkcs8).getPrivateKey().getOctets();
    }

    // ---- the cells -------------------------------------------------------

    @Test
    public void rsaCrtDsaAndDhPkcs8Identical() throws Exception
    {
        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA", jsl);
        rg.initialize(2048);
        RSAPrivateCrtKey rsa = (RSAPrivateCrtKey) rg.generateKeyPair().getPrivate();
        KeySpec crt = new RSAPrivateCrtKeySpec(rsa.getModulus(), rsa.getPublicExponent(),
                rsa.getPrivateExponent(), rsa.getPrimeP(), rsa.getPrimeQ(),
                rsa.getPrimeExponentP(), rsa.getPrimeExponentQ(), rsa.getCrtCoefficient());
        assertCell("RSA (CRT spec)", "RSA", crt, crt);

        KeyPairGenerator dg = KeyPairGenerator.getInstance("DSA", jsl);
        dg.initialize(2048);
        DSAPrivateKey dsa = (DSAPrivateKey) dg.generateKeyPair().getPrivate();
        KeySpec ds = new DSAPrivateKeySpec(dsa.getX(), dsa.getParams().getP(),
                dsa.getParams().getQ(), dsa.getParams().getG());
        assertCell("DSA", "DSA", ds, ds);

        // 2048, not 1024: jostle serves the RFC 7919 group sizes only.
        KeyPairGenerator hg = KeyPairGenerator.getInstance("DH", jsl);
        hg.initialize(2048);
        DHPrivateKey dh = (DHPrivateKey) hg.generateKeyPair().getPrivate();
        KeySpec hs = new DHPrivateKeySpec(dh.getX(), dh.getParams().getP(), dh.getParams().getG());
        assertCell("DH", "DH", hs, hs);
    }

    /** Both sides emit the bare {@code expandedKey} OCTET STRING (0x04) and agree. */
    @Test
    public void postQuantumExpandedFormPkcs8Identical() throws Exception
    {
        for (String alg : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
        {
            MLDSAPrivateKey k = (MLDSAPrivateKey) KeyPairGenerator.getInstance(alg, jsl)
                    .generateKeyPair().getPrivate();
            byte[] expanded = k.getPrivateData();
            Assertions.assertNotNull(expanded, alg + ": no expanded private data to share");
            assertCell(alg + " (expanded)", alg,
                    new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(alg), expanded, null),
                    new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(
                            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.fromName(alg), expanded, null));
        }

        for (String alg : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            MLKEMPrivateKey k = (MLKEMPrivateKey) KeyPairGenerator.getInstance(alg, jsl)
                    .generateKeyPair().getPrivate();
            byte[] expanded = k.getPrivateData();
            Assertions.assertNotNull(expanded, alg + ": no expanded private data to share");
            assertCell(alg + " (expanded)", alg,
                    new MLKEMPrivateKeySpec(MLKEMParameterSpec.fromName(alg), expanded, null),
                    new org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec(
                            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.fromName(alg), expanded, null));
        }
    }

    // ---- the pins --------------------------------------------------------

    /**
     * EC pin one, caused by the INPUT. A plain {@code ECParameterSpec} carries
     * no curve name, so jostle recovers it by matching and BC emits explicit
     * parameters. RFC 5480 section 2.1.1: "implicitCurve and specifiedCurve
     * MUST NOT be used in PKIX", so only ours is the PKIX arm.
     */
    @Test
    public void ecNamelessSpecEmitsNamedCurveOursAndSpecifiedCurveTheirs() throws Exception
    {
        for (String curve : EC_CURVES)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
            g.initialize(new ECGenParameterSpec(curve));
            ECPrivateKey gen = (ECPrivateKey) g.generateKeyPair().getPrivate();
            KeySpec nameless = new ECPrivateKeySpec(gen.getS(), gen.getParams());

            byte[] ours = encode(jsl, "EC", nameless);
            byte[] theirs = encode(bc, "EC", nameless);

            Assertions.assertFalse(Arrays.areEqual(ours, theirs),
                    "EC " + curve + ": nameless-spec divergence has closed — re-measure the pin");
            Assertions.assertTrue(ours.length < theirs.length,
                    "EC " + curve + ": ours must be the shorter named form");
            Assertions.assertTrue(algIdOf(ours).length < algIdOf(theirs).length,
                    "EC " + curve + ": the divergence must be in the AlgorithmIdentifier");
            Assertions.assertTrue(Arrays.areEqual(scalarOf(ours), scalarOf(theirs)),
                    "EC " + curve + ": the privateKey OCTET STRING must agree");
        }
    }

    /**
     * EC pin two, the ENCODERS. With a name-carrying spec the AlgorithmIdentifier
     * agrees, and what remains is the optional ECPrivateKey field. RFC 5915
     * section 3 says conforming implementations MUST include parameters and
     * SHOULD include publicKey: BC meets the MUST, we meet the SHOULD. Ours is
     * OpenSSL's deliberate PKCS#8 form — {@code EC_PKEY_NO_PARAMETERS} in
     * {@code encode_key2any.c}, commented as such in 3.1.2 and 3.5.8.
     */
    @Test
    public void ecNamedSpecStillDivergesOnTheOptionalEcPrivateKeyField() throws Exception
    {
        for (String curve : EC_CURVES)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
            g.initialize(new ECGenParameterSpec(curve));
            ECPrivateKey gen = (ECPrivateKey) g.generateKeyPair().getPrivate();

            byte[] ours = encode(jsl, "EC", new ECPrivateKeySpec(gen.getS(), namedParams(jsl, curve)));
            byte[] theirs = encode(bc, "EC", new ECPrivateKeySpec(gen.getS(), namedParams(bc, curve)));

            Assertions.assertArrayEquals(algIdOf(ours), algIdOf(theirs),
                    "EC " + curve + ": a name-carrying spec must give both the same AlgorithmIdentifier");
            Assertions.assertTrue(Arrays.areEqual(scalarOf(ours), scalarOf(theirs)),
                    "EC " + curve + ": the privateKey OCTET STRING must agree");

            Assertions.assertEquals(1, optionalTagOf(ours),
                    "EC " + curve + ": jostle must attach [1] publicKey");
            Assertions.assertEquals(0, optionalTagOf(theirs),
                    "EC " + curve + ": BC must attach [0] parameters");
        }
    }

    /** The scalar from inside an EC PKCS#8's RFC 5915 ECPrivateKey. */
    private static byte[] scalarOf(byte[] pkcs8) throws Exception
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(
                PrivateKeyInfo.getInstance(pkcs8).parsePrivateKey());
        return ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    /** The tag number of the single optional field in an ECPrivateKey. */
    private static int optionalTagOf(byte[] pkcs8) throws Exception
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(
                PrivateKeyInfo.getInstance(pkcs8).parsePrivateKey());
        Assertions.assertEquals(3, seq.size(), "expected exactly one optional ECPrivateKey field");
        return ASN1TaggedObject.getInstance(seq.getObjectAt(2)).getTagNo();
    }

    /**
     * Edwards pin. RFC 5958 section 2: "If publicKey is present, then version
     * is set to v2 else version is set to v1"; RFC 8410 section 7 permits
     * either. Ours omits the public half, BC attaches it. The positive half
     * asserts the algorithm identifier and CurvePrivateKey bytes are identical,
     * so version plus the attachment is the whole difference.
     *
     * <p>{@code XECMontgomery} reads jostle's PKCS#8 by fixed 48/72-byte
     * layout, so a move to version 1 changes reader and writer together.
     */
    @Test
    public void edwardsPinVersionAndAttachedPublicKey() throws Exception
    {
        for (String alg : new String[]{"Ed25519", "Ed448"})
        {
            EdECPrivateKey gen = (EdECPrivateKey) KeyPairGenerator.getInstance(alg, jsl)
                    .generateKeyPair().getPrivate();
            byte[] raw = gen.getBytes().orElseThrow(
                    () -> new AssertionError(alg + ": generated key exposes no raw scalar"));
            KeySpec spec = new EdECPrivateKeySpec(new NamedParameterSpec(alg), raw);

            byte[] ours = encode(jsl, alg, spec);
            byte[] theirs = encode(bc, alg, spec);

            Assertions.assertFalse(Arrays.areEqual(ours, theirs),
                    alg + ": divergence has closed — re-measure the pin");
            Assertions.assertEquals(0, versionOf(ours), alg + ": jostle must emit version 0");
            Assertions.assertEquals(1, versionOf(theirs), alg + ": BC must emit version 1");
            Assertions.assertTrue(ours.length < theirs.length,
                    alg + ": ours must be the shorter form");

            Assertions.assertArrayEquals(algIdOf(ours), algIdOf(theirs),
                    alg + ": AlgorithmIdentifier must be identical");
            Assertions.assertArrayEquals(privateKeyOctetsOf(ours), privateKeyOctetsOf(theirs),
                    alg + ": the CurvePrivateKey OCTET STRING must be identical");
        }
    }

    private static int versionOf(byte[] pkcs8) throws Exception
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(pkcs8);
        return ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
    }

    /**
     * PQ seed pin, an annotation on the six PQ cells. RFC 9881 section 6 and
     * RFC 9935 section 6: "the seed format is RECOMMENDED". From a seed spec
     * jostle emits it and BC expands to the both arm. The positive half is an
     * expansion-agreement witness — BC's bytes equal jostle's own generated
     * encoding — so the divergence is arm selection, not content.
     */
    @Test
    public void postQuantumSeedFormPinSeedArmVersusBothArm() throws Exception
    {
        for (String alg : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, jsl).generateKeyPair();
            MLDSAPrivateKey k = (MLDSAPrivateKey) kp.getPrivate();
            byte[] seed = k.getSeed();
            Assertions.assertNotNull(seed, alg + ": generated key exposes no seed");
            Assertions.assertEquals(32, seed.length, alg + ": RFC 9881 section 6 fixes the seed at 32 bytes");

            byte[] ours = encode(jsl, alg,
                    new MLDSAPrivateKeySpec(MLDSAParameterSpec.fromName(alg), seed));
            byte[] theirs = encode(bc, alg,
                    new org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec(
                            org.bouncycastle.jcajce.spec.MLDSAParameterSpec.fromName(alg), seed));
            assertSeedArmPin(alg, ours, theirs, k.getEncoded());
        }

        for (String alg : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, jsl).generateKeyPair();
            MLKEMPrivateKey k = (MLKEMPrivateKey) kp.getPrivate();
            byte[] seed = k.getSeed();
            Assertions.assertNotNull(seed, alg + ": generated key exposes no seed");
            Assertions.assertEquals(64, seed.length, alg + ": RFC 9935 section 6 fixes the seed at 64 bytes");

            byte[] ours = encode(jsl, alg,
                    new MLKEMPrivateKeySpec(MLKEMParameterSpec.fromName(alg), seed));
            byte[] theirs = encode(bc, alg,
                    new org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec(
                            org.bouncycastle.jcajce.spec.MLKEMParameterSpec.fromName(alg), seed));
            assertSeedArmPin(alg, ours, theirs, k.getEncoded());
        }
    }

    private static void assertSeedArmPin(String alg, byte[] ours, byte[] theirs, byte[] generated)
            throws Exception
    {
        Assertions.assertFalse(Arrays.areEqual(ours, theirs),
                alg + ": seed-form divergence has closed — re-measure the pin");
        Assertions.assertEquals(0x80, armTagOf(ours), alg + ": jostle must emit the seed [0] arm");
        Assertions.assertEquals(0x30, armTagOf(theirs), alg + ": BC must emit the both SEQUENCE arm");
        Assertions.assertEquals(0x30, armTagOf(generated),
                alg + ": jostle's own generated key must carry the both arm");
        Assertions.assertTrue(Arrays.areEqual(theirs, generated),
                alg + ": BC's expansion of the seed must equal jostle's generated encoding");
    }

    /** First byte of the privateKey OCTET STRING contents — the CHOICE arm's tag. */
    private static int armTagOf(byte[] pkcs8) throws Exception
    {
        byte[] inner = privateKeyOctetsOf(pkcs8);
        Assertions.assertTrue(inner.length > 0, "empty privateKey OCTET STRING");
        return inner[0] & 0xff;
    }

    /**
     * RSA pin, an annotation on the RSA cell. Given a CRT-less
     * {@code RSAPrivateKeySpec} jostle refuses, because OpenSSL needs the
     * public exponent to build an EVP_PKEY; BC accepts and writes zero for
     * publicExponent and all five CRT fields, every one of which RFC 8017
     * A.1.2 makes mandatory. Type is asserted, not message text, per the
     * BC-exception-parity rule.
     */
    @Test
    public void rsaPlainSpecPinWeRefuseAndBcEmitsZeroCrtFields() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", jsl);
        g.initialize(2048);
        RSAPrivateCrtKey gen = (RSAPrivateCrtKey) g.generateKeyPair().getPrivate();
        KeySpec plain = new RSAPrivateKeySpec(gen.getModulus(), gen.getPrivateExponent());

        InvalidKeySpecException ours = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> KeyFactory.getInstance("RSA", jsl).generatePrivate(plain),
                "jostle must refuse a CRT-less RSAPrivateKeySpec");
        Assertions.assertTrue(ours.getMessage().contains("CRT"),
                "the refusal must name the missing CRT components: " + ours.getMessage());

        byte[] theirs = encode(bc, "RSA", plain);
        ASN1Sequence rsa = ASN1Sequence.getInstance(privateKeyOctetsOf(theirs));
        Assertions.assertEquals(9, rsa.size(), "expected an RFC 8017 two-prime RSAPrivateKey");

        assertFieldPresent(rsa, 1, "modulus");
        assertFieldPresent(rsa, 3, "privateExponent");

        assertFieldZero(rsa, 2, "publicExponent");
        assertFieldZero(rsa, 4, "prime1");
        assertFieldZero(rsa, 5, "prime2");
        assertFieldZero(rsa, 6, "exponent1");
        assertFieldZero(rsa, 7, "exponent2");
        assertFieldZero(rsa, 8, "coefficient");
    }

    private static void assertFieldZero(ASN1Sequence rsa, int index, String name)
    {
        Assertions.assertEquals(0, ASN1Integer.getInstance(rsa.getObjectAt(index)).getValue().signum(),
                "BC must leave " + name + " zero when the spec carried none");
    }

    private static void assertFieldPresent(ASN1Sequence rsa, int index, String name)
    {
        Assertions.assertEquals(1, ASN1Integer.getInstance(rsa.getObjectAt(index)).getValue().signum(),
                name + " must be present — the spec carried it");
    }

    // ---- the block guards ------------------------------------------------

    /** BC has no {@code XECPrivateKeySpec} branch; a bcprov bump that adds one turns this red. */
    @Test
    public void xecBlockStillHoldsBecauseBcRejectsTheJdkSpec() throws Exception
    {
        for (String alg : new String[]{"X25519", "X448"})
        {
            XECPrivateKey gen = (XECPrivateKey) KeyPairGenerator.getInstance(alg, jsl)
                    .generateKeyPair().getPrivate();
            byte[] raw = gen.getScalar().orElseThrow(
                    () -> new AssertionError(alg + ": generated key exposes no scalar"));
            KeySpec spec = new XECPrivateKeySpec(new NamedParameterSpec(alg), raw);

            Assertions.assertNotNull(encode(jsl, alg, spec), alg + ": jostle must accept the JDK spec");

            Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> KeyFactory.getInstance(alg, bc).generatePrivate(spec),
                    alg + ": BC now accepts XECPrivateKeySpec — promote this block to a cell");
        }
    }

    /** BC ships no SLH-DSA private key spec, so no shared material exists. */
    @Test
    public void slhdsaBlockStillHoldsBecauseBcShipsNoPrivateKeySpec()
    {
        Assertions.assertThrows(ClassNotFoundException.class,
                () -> Class.forName("org.bouncycastle.jcajce.spec.SLHDSAPrivateKeySpec"),
                "BC now ships SLHDSAPrivateKeySpec — promote the twelve blocks to cells");

        Assertions.assertDoesNotThrow(
                () -> Class.forName("org.openssl.jostle.jcajce.spec.SLHDSAPrivateKeySpec"),
                "jostle must still have its own SLH-DSA private key spec");
    }
}
