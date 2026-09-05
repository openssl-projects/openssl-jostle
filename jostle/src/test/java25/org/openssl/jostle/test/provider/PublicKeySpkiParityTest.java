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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * Group C item 2: for every KeyPairGenerator family JSL and BC share, the same
 * PUBLIC key built on both sides from a shared input must encode to
 * byte-identical X.509 SubjectPublicKeyInfo.
 *
 * <p><b>Lives in {@code src/test/java25} deliberately.</b>
 * {@code java.security.interfaces.EdECPublicKey} and
 * {@code EdECPublicKeySpec} are Java 15 APIs and {@code src/test/java}
 * compiles at release 8, so this cannot sit beside the other provider tests.
 * The {@code unitTest25*} tasks run both source sets together.
 *
 * <h2>Why a shared spec and no decoder</h2>
 *
 * <p>Decode-and-re-encode equality proves ACCEPTANCE, not encoder agreement: a
 * decoder that retained its input would satisfy it while agreeing about
 * nothing. So each provider is handed the same MATERIAL — components, a point,
 * or raw bytes — and builds its own key; the encodings are then compared with
 * no decode in the path.
 *
 * <p>Scope is public keys only (Megan, 2026-09-05). Private-key/PKCS#8 parity
 * is held until after the merge.
 *
 * <h2>Every shared family is in exactly one of three states</h2>
 *
 * <p>CELL (byte equality asserted), PINNED (an explained divergence), or
 * BLOCKED (named reason). A family in none of the three FAILS
 * {@link #everySharedFamilyIsAccountedFor} — a fourth state is how a family
 * goes quietly unexamined.
 *
 * <p>Measured 2026-09-05: 26 shared families. 12 are cells, 14 are blocked, and
 * EC additionally carries a pinned divergence.
 *
 * <h2>The blocks, with reasons</h2>
 *
 * <ol>
 *   <li>X25519, X448 — {@code JOXECPublicKey} implements only
 *       {@code PublicKey}, {@code XDHKey}, {@code OSSLKey}, NOT
 *       {@code java.security.interfaces.XECPublicKey}, and
 *       {@code XECKeyFactorySpi} rejects {@code XECPublicKeySpec} as "Java 11+
 *       and out of scope". So no shared material can be extracted. Registered
 *       as a finding; the Ed families DO implement their JDK interface
 *       ({@code java15/JOEdPublicKey}), so this is an asymmetry inside jostle
 *       rather than a JDK limitation.</li>
 *   <li>SLH-DSA, all twelve — BC ships {@code SLHDSAParameterSpec} but NO
 *       {@code SLHDSAPublicKeySpec}, so BC cannot be handed raw bytes. jostle
 *       has {@code SLHDSAPublicKeySpec}; the gap is one-sided. Routing through
 *       {@code X509EncodedKeySpec} instead would put a decoder in the loop and
 *       measure acceptance rather than agreement, so it is deliberately NOT
 *       done.</li>
 * </ol>
 */
public class PublicKeySpkiParityTest
{
    private static Provider jsl;
    private static Provider bc;

    /** Families compared byte-for-byte. */
    private static final TreeSet<String> CELLS = new TreeSet<String>(java.util.Arrays.asList(
            "RSA", "DSA", "DH", "EC",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"));

    /** Families blocked, with the reason in the class javadoc. */
    private static final TreeMap<String, String> BLOCKED = new TreeMap<String, String>();

    /**
     * DER of OBJECT IDENTIFIER 1.2.840.10045.3.1.7 (secp256r1), tag and length
     * included. Hard-coded deliberately: this is a fixed ASN.1 constant that
     * OpenSSL does not own, so it is outside the query-don't-transcribe rule.
     */
    private static final byte[] SECP256R1_OID_DER = {
            (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07};

    /** Curves for the EC cell — both providers serve all four (measured). */
    private static final String[] EC_CURVES = {"secp256r1", "secp384r1", "secp521r1", "secp256k1"};

    static
    {
        BLOCKED.put("X25519", "JOXECPublicKey has no XECPublicKey interface; KeyFactory rejects XECPublicKeySpec");
        BLOCKED.put("X448", "JOXECPublicKey has no XECPublicKey interface; KeyFactory rejects XECPublicKeySpec");
        BLOCKED.put("ED25519", "EdKeyFactorySpi rejects the JDK EdECPublicKeySpec; EdDSAPublicKey has no raw getter");
        BLOCKED.put("ED448", "EdKeyFactorySpi rejects the JDK EdECPublicKeySpec; EdDSAPublicKey has no raw getter");
        for (String h : new String[]{"SHA2", "SHAKE"})
        {
            for (String s : new String[]{"128", "192", "256"})
            {
                for (String v : new String[]{"S", "F"})
                {
                    BLOCKED.put("SLH-DSA-" + h + "-" + s + v, "BC ships no SLHDSAPublicKeySpec");
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
     * The completeness guard the design turns on: every shared family is a
     * cell or a named block, never a fourth state. Read from the LIVE
     * providers, so a newly shared family arrives as a failure.
     */
    @Test
    public void everySharedFamilyIsAccountedFor()
    {
        TreeSet<String> shared = shared();
        Assertions.assertFalse(shared.isEmpty(), "vacuity: no shared KeyPairGenerator families");

        List<String> unaccounted = new ArrayList<String>();
        for (String f : shared)
        {
            if (!CELLS.contains(f) && !BLOCKED.containsKey(f))
            {
                unaccounted.add(f);
            }
        }
        Assertions.assertTrue(unaccounted.isEmpty(),
                "shared families in no state — add a cell or a named block, do not leave them:\n  "
                        + String.join("\n  ", unaccounted));

        // And the reverse: a cell or block naming a family that is no longer
        // shared is a dead entry, which hides a lost family.
        List<String> stale = new ArrayList<String>();
        for (String f : CELLS)
        {
            if (!shared.contains(f))
            {
                stale.add("CELL " + f);
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

        Assertions.assertEquals(shared.size(), CELLS.size() + BLOCKED.size(),
                "tally must equal the shared set: " + shared.size() + " shared, "
                        + CELLS.size() + " cells + " + BLOCKED.size() + " blocked");
    }

    // ---- the cells -------------------------------------------------------

    @Test
    public void rsaDsaDhSpkiIdentical() throws Exception
    {
        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA", jsl);
        rg.initialize(2048);
        RSAPublicKey rsa = (RSAPublicKey) rg.generateKeyPair().getPublic();
        assertSpecBuiltAgree("RSA", rsa,
                new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));

        KeyPairGenerator dg = KeyPairGenerator.getInstance("DSA", jsl);
        dg.initialize(1024);
        DSAPublicKey dsa = (DSAPublicKey) dg.generateKeyPair().getPublic();
        assertSpecBuiltAgree("DSA", dsa, new DSAPublicKeySpec(
                dsa.getY(), dsa.getParams().getP(), dsa.getParams().getQ(),
                dsa.getParams().getG()));

        // 2048, not 1024: jostle serves the RFC 7919 group sizes only, which is
        // correct behaviour and not a finding.
        KeyPairGenerator hg = KeyPairGenerator.getInstance("DH", jsl);
        hg.initialize(2048);
        DHPublicKey dh = (DHPublicKey) hg.generateKeyPair().getPublic();
        assertSpecBuiltAgree("DH", dh, new DHPublicKeySpec(
                dh.getY(), dh.getParams().getP(), dh.getParams().getG()));
    }

    /**
     * FINDING C, pinned rather than described: jostle hands out a
     * JDK-standard Ed public key and will not take one back.
     *
     * <p>{@code java15/JOEdPublicKey} implements
     * {@code java.security.interfaces.EdECPublicKey}, so a caller can READ the
     * key through the JDK interface — and {@code EdKeyFactorySpi} (which has
     * only a {@code java/} copy) accepts just {@code X509EncodedKeySpec} and
     * jostle's own {@code EdDSAPublicKeySpec}, so the same caller cannot WRITE
     * one back. BC accepts the JDK spec, so the gap is one-sided and ours.
     *
     * <p>There is no raw-bytes fallback either: jostle's
     * {@code EdDSAPublicKey} interface declares no methods, while
     * {@code MLDSAPublicKey} and {@code SLHDSAPublicKey} both declare
     * {@code getPublicData()}. That is why ED25519/ED448 are BLOCKED here
     * rather than compared — no symmetric route exists.
     *
     * <p>Found by making the comparison symmetric (the same spec through both
     * KeyFactories). The earlier asymmetric form — jostle's GENERATED key
     * against BC's spec-built key — passed while this was false.
     *
     * <p>When the gap is closed, this test fails and ED25519/ED448 move back
     * to {@link #CELLS}. It is written to fail on the fix, deliberately.
     */
    @Test
    public void edwardsKeysAreReadableButNotWritableThroughTheJdkSpec() throws Exception
    {
        for (String alg : new String[]{"ED25519", "ED448"})
        {
            EdECPublicKey ed = (EdECPublicKey) KeyPairGenerator.getInstance(alg, jsl)
                    .generateKeyPair().getPublic();
            EdECPublicKeySpec jdkSpec = new EdECPublicKeySpec(ed.getParams(), ed.getPoint());

            // BC takes it.
            PublicKey bcPub = KeyFactory.getInstance(alg, bc).generatePublic(jdkSpec);
            Assertions.assertNotNull(bcPub, alg + ": BC must accept the JDK spec");

            // jostle does not. Typed, per the KeyFactory contract.
            Assertions.assertThrows(java.security.spec.InvalidKeySpecException.class,
                    () -> KeyFactory.getInstance(alg, jsl).generatePublic(jdkSpec),
                    alg + ": if jostle now ACCEPTS the JDK spec, finding C is fixed —"
                            + " move " + alg + " into CELLS and delete this test");

            // The encoded route still works both ways, which is why this is an
            // interop inconvenience rather than a total block.
            byte[] spki = ed.getEncoded();
            Assertions.assertTrue(Arrays.areEqual(spki,
                            KeyFactory.getInstance(alg, jsl)
                                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki))
                                    .getEncoded()),
                    alg + ": the X509 route must still round-trip");
        }
    }

    /**
     * EC, with the input that does NOT lose the curve name: each provider
     * derives its own {@code ECParameterSpec} from the NAME through its own
     * {@code AlgorithmParameters}, so BC gets its name-carrying
     * {@code ECNamedCurveSpec} and jostle recovers the name by matching. The
     * shared material is (curve name, point W).
     */
    @Test
    public void ecSpkiIdenticalWhenTheSpecCarriesTheCurveName() throws Exception
    {
        for (String curve : EC_CURVES)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
            g.initialize(new ECGenParameterSpec(curve));
            ECPublicKey gen = (ECPublicKey) g.generateKeyPair().getPublic();

            PublicKey ours = KeyFactory.getInstance("EC", jsl)
                    .generatePublic(new ECPublicKeySpec(gen.getW(), namedParams(jsl, curve)));
            PublicKey theirs = KeyFactory.getInstance("EC", bc)
                    .generatePublic(new ECPublicKeySpec(gen.getW(), namedParams(bc, curve)));
            Assertions.assertTrue(Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()),
                    "EC " + curve + ": SPKI differs when both specs carry the name");
        }
    }

    private static ECParameterSpec namedParams(Provider p, String curve) throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", p);
        ap.init(new ECGenParameterSpec(curve));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    /**
     * The PINNED divergence. A plain {@code java.security.spec.ECPublicKeySpec}
     * carries no curve NAME, only the numbers — so from the SAME nameless spec
     * jostle emits the named form and BC emits explicit parameters. Both are
     * valid SPKI and the difference is explained by the lossy INPUT, not by the
     * encoders.
     *
     * <p>Asserted here: the divergence itself, that jostle produces the
     * SHORTER named form (the property a caller depends on for interop), and
     * that each provider still reads the other's bytes. A future change that
     * made jostle emit explicit parameters would fail this.
     */
    @Test
    public void ecNamelessSpecDivergenceIsPinned() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
        g.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey gen = (ECPublicKey) g.generateKeyPair().getPublic();
        ECPublicKeySpec nameless = new ECPublicKeySpec(gen.getW(), gen.getParams());

        byte[] ours = KeyFactory.getInstance("EC", jsl).generatePublic(nameless).getEncoded();
        byte[] theirs = KeyFactory.getInstance("EC", bc).generatePublic(nameless).getEncoded();

        Assertions.assertFalse(Arrays.areEqual(ours, theirs),
                "the nameless-spec divergence is gone — if BC now emits the named form,"
                        + " promote this to a byte-equality cell rather than deleting it");

        // Structure, not length: a shorter explicit form or a longer named one
        // would both satisfy a length comparison while meaning the opposite.
        // In an SPKI the AlgorithmIdentifier's parameters element is either an
        // OBJECT IDENTIFIER (0x06, named curve) or a SEQUENCE (0x30, explicit).
        Assertions.assertEquals(0x06, spkiParamsTag(ours),
                "jostle must emit a NAMED curve — parameters must be an OBJECT IDENTIFIER");
        Assertions.assertEquals(0x30, spkiParamsTag(theirs),
                "BC from a nameless spec must emit EXPLICIT parameters — a SEQUENCE");
        // And the OID must be secp256r1 itself, not merely some OID.
        Assertions.assertTrue(Arrays.areEqual(SECP256R1_OID_DER, spkiParamsDer(ours)),
                "jostle's named parameters must be the secp256r1 OID 1.2.840.10045.3.1.7");

        // Each still reads the other's bytes, so this is not a parsing defect.
        Assertions.assertNotNull(KeyFactory.getInstance("EC", bc)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(ours)));
        Assertions.assertNotNull(KeyFactory.getInstance("EC", jsl)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(theirs)));
    }

    /**
     * ML-DSA and ML-KEM. Neither provider's spec CLASS is shared — each has its
     * own same-named one — so the shared material is the raw public-key byte
     * array, wrapped per provider. BC's parameter constant is reached through
     * {@code fromName}, which is stable across the field names.
     */
    @Test
    public void mlDsaAndMlKemSpkiIdentical() throws Exception
    {
        String[][] fams = {
                {"ML-DSA-44", "ml-dsa-44"}, {"ML-DSA-65", "ml-dsa-65"}, {"ML-DSA-87", "ml-dsa-87"},
                {"ML-KEM-512", "ml-kem-512"}, {"ML-KEM-768", "ml-kem-768"}, {"ML-KEM-1024", "ml-kem-1024"},
        };
        for (String[] f : fams)
        {
            PublicKey pub = KeyPairGenerator.getInstance(f[0], jsl).generateKeyPair().getPublic();
            byte[] raw;
            boolean dsa = f[0].startsWith("ML-DSA");
            if (dsa)
            {
                raw = ((MLDSAPublicKey) pub).getPublicData();
            }
            else
            {
                raw = ((MLKEMPublicKey) pub).getPublicData();
            }
            Assertions.assertTrue(raw != null && raw.length > 0, f[0] + ": no raw public data");

            // Direct classes, not Class.forName: bcprov is on the test
            // classpath, so the compiler witnesses these names. fromName is
            // used rather than the constants because BC's fields are
            // lower-case (ml_dsa_44) and fromName is the stable accessor.
            java.security.spec.KeySpec bcSpec;
            if (dsa)
            {
                bcSpec = new org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec(
                        org.bouncycastle.jcajce.spec.MLDSAParameterSpec.fromName(f[1]), raw);
            }
            else
            {
                bcSpec = new org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec(
                        org.bouncycastle.jcajce.spec.MLKEMParameterSpec.fromName(f[1]), raw);
            }
            PublicKey bcPub = KeyFactory.getInstance(f[0], bc).generatePublic(bcSpec);
            Assertions.assertTrue(Arrays.areEqual(pub.getEncoded(), bcPub.getEncoded()),
                    f[0] + ": SPKI differs (jostle " + pub.getEncoded().length
                            + ", BC " + bcPub.getEncoded().length + ")");
            // Symmetry: jostle's own KeyFactory from ITS spec must agree too,
            // so a jostle generator/KeyFactory disagreement cannot hide.
            java.security.spec.KeySpec ourSpec = dsa
                    ? new org.openssl.jostle.jcajce.spec.MLDSAPublicKeySpec(
                            org.openssl.jostle.jcajce.spec.MLDSAParameterSpec.fromName(f[1]), raw)
                    : new org.openssl.jostle.jcajce.spec.MLKEMPublicKeySpec(
                            org.openssl.jostle.jcajce.spec.MLKEMParameterSpec.fromName(f[1]), raw);
            PublicKey oursFromSpec = KeyFactory.getInstance(f[0], jsl).generatePublic(ourSpec);
            Assertions.assertTrue(Arrays.areEqual(pub.getEncoded(), oursFromSpec.getEncoded()),
                    f[0] + ": jostle's generator and KeyFactory disagree");
        }
    }

    /**
     * WHY the round-trip shape is not a witness of encoder agreement — shown,
     * not asserted in the abstract.
     *
     * <p>Measured on EC: both providers PRESERVE the form they were given.
     * jostle handed BC's 311-byte explicit-parameter SPKI re-emits 311 bytes;
     * BC handed jostle's 91-byte named SPKI re-emits 91. Each is honouring the
     * caller's parameters, which is correct — and it means "decode the other
     * provider's bytes and re-encode equal" passes for BOTH providers while
     * they demonstrably do NOT agree on how to encode the same key.
     *
     * <p>So a decode-and-re-encode comparison is coverage; the witness is a
     * from-shared-material comparison, which is what every cell above does.
     * This test exists to keep that reasoning attached to a measurement rather
     * than a claim, and it fails if either provider starts rewriting the form
     * it was handed — which would ALSO be a caller-visible change.
     *
     * <p>Contrast {@code AlgorithmParametersNameCompleteSmokeTest}, where both
     * providers were measured to RE-DERIVE, dropping an explicitly-stated
     * default. Whether a decoder preserves or canonicalises is per-surface and
     * must be measured, never assumed either way.
     */
    @Test
    public void bothProvidersPreserveTheEncodingFormTheyAreGiven() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
        g.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey gen = (ECPublicKey) g.generateKeyPair().getPublic();
        ECPublicKeySpec nameless = new ECPublicKeySpec(gen.getW(), gen.getParams());

        byte[] explicitForm = KeyFactory.getInstance("EC", bc)
                .generatePublic(nameless).getEncoded();
        byte[] namedForm = KeyFactory.getInstance("EC", jsl)
                .generatePublic(nameless).getEncoded();
        Assertions.assertFalse(Arrays.areEqual(explicitForm, namedForm),
                "precondition: the two forms must differ for this test to mean anything");

        byte[] jslGivenExplicit = KeyFactory.getInstance("EC", jsl)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(explicitForm))
                .getEncoded();
        Assertions.assertTrue(Arrays.areEqual(explicitForm, jslGivenExplicit),
                "jostle must PRESERVE explicit parameters it was given, not rewrite them to"
                        + " the named form; got " + jslGivenExplicit.length
                        + " from " + explicitForm.length);

        byte[] bcGivenNamed = KeyFactory.getInstance("EC", bc)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(namedForm))
                .getEncoded();
        Assertions.assertTrue(Arrays.areEqual(namedForm, bcGivenNamed),
                "BC must PRESERVE the named form it was given; got " + bcGivenNamed.length
                        + " from " + namedForm.length);
    }

    /**
     * The symmetric comparison Megan's rule actually asks for: the SAME spec
     * built through BOTH providers' KeyFactory, so two identical construction
     * paths are compared.
     *
     * <p>Also asserts, separately, that jostle's GENERATOR and jostle's own
     * KeyFactory agree — a jostle-internal property that a
     * generator-versus-BC comparison could not see, and the gap this method
     * closes.
     */
    private static void assertSpecBuiltAgree(String alg, PublicKey generated,
                                             java.security.spec.KeySpec spec) throws Exception
    {
        PublicKey ours = KeyFactory.getInstance(alg, jsl).generatePublic(spec);
        PublicKey theirs = KeyFactory.getInstance(alg, bc).generatePublic(spec);
        Assertions.assertTrue(Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()),
                alg + ": SPKI differs from the SAME spec — jostle "
                        + ours.getEncoded().length + " bytes, BC " + theirs.getEncoded().length);
        Assertions.assertTrue(Arrays.areEqual(generated.getEncoded(), ours.getEncoded()),
                alg + ": jostle's GENERATOR and jostle's KeyFactory encode the same key"
                        + " differently — generated " + generated.getEncoded().length
                        + ", spec-built " + ours.getEncoded().length);
    }

    /** The DER tag of the AlgorithmIdentifier's parameters element in an SPKI. */
    private static int spkiParamsTag(byte[] spki)
    {
        int i = skipHeader(spki, 0, 0x30);      // outer SEQUENCE
        i = skipHeader(spki, i, 0x30);          // AlgorithmIdentifier SEQUENCE
        i = skipValue(spki, i, 0x06);           // algorithm OID
        Assertions.assertTrue(i < spki.length, "SPKI AlgorithmIdentifier has no parameters");
        return spki[i] & 0xFF;
    }

    /** The parameters element's full DER bytes, tag included. */
    private static byte[] spkiParamsDer(byte[] spki)
    {
        int i = skipHeader(spki, 0, 0x30);
        i = skipHeader(spki, i, 0x30);
        i = skipValue(spki, i, 0x06);
        int end = skipValue(spki, i, spki[i] & 0xFF);
        return java.util.Arrays.copyOfRange(spki, i, end);
    }

    /** Consume tag+length, returning the offset of the CONTENT. */
    private static int skipHeader(byte[] b, int i, int expectTag)
    {
        Assertions.assertEquals(expectTag, b[i] & 0xFF,
                "expected DER tag 0x" + Integer.toHexString(expectTag) + " at " + i);
        i++;
        int len = b[i++] & 0xFF;
        if ((len & 0x80) != 0)
        {
            i += (len & 0x7F);                 // long form: skip the length bytes
        }
        return i;
    }

    /** Consume a whole TLV, returning the offset just past it. */
    private static int skipValue(byte[] b, int i, int expectTag)
    {
        Assertions.assertEquals(expectTag, b[i] & 0xFF,
                "expected DER tag 0x" + Integer.toHexString(expectTag) + " at " + i);
        i++;
        int len = b[i++] & 0xFF;
        if ((len & 0x80) != 0)
        {
            int n = len & 0x7F;
            len = 0;
            for (int k = 0; k < n; k++)
            {
                len = (len << 8) | (b[i++] & 0xFF);
            }
        }
        return i + len;
    }
}
