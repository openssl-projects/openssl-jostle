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

package org.openssl.jostle.test.ec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.EcCurves;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

/**
 * EC domain parameters come from OpenSSL's builtin curve table, in both
 * directions, and agree with the platform on every curve both know.
 *
 * <p><b>What this replaced, and what it was worth.</b> {@code ECComponents}
 * used to resolve a curve name through a platform {@code AlgorithmParameters}
 * and reverse-resolve by brute-forcing a hardcoded 16-entry list. Measured on
 * a bare JVM across all 82 curves the loaded build serves, before the change:
 * 82 generated a keypair, 43 of those then threw {@code IllegalStateException}
 * from {@code getParams()}, another 24 could not be rebuilt from an
 * {@code ECPrivateKeySpec}, and 15 worked end to end. Identical on JDK 8, 11,
 * 17, 21 and 25 — the cap was ours, not the platform's.
 *
 * <p><b>Why the comparison is against SunEC and not against ourselves.</b> A
 * lookup stubbed to answer one fixed curve satisfies every self-consistency
 * check that could be written here — encode/decode round-trips, name in equals
 * name out. Only an independent implementation of the same table detects it,
 * so the sweep compares field, curve, generator, order and cofactor against
 * the platform's answer for every curve the platform also knows.
 */
public class ECCurveTableTest
{
    private static Provider jsl;

    /**
     * Snapshot of OpenSSL 3.5.x's builtin curve table, used only to DRIVE the
     * sweep — it is not a source of truth and a name the loaded build does not
     * know is skipped rather than failed, so a build configured without binary
     * fields still passes. The floors below are what stop that skipping from
     * turning the sweep vacuous.
     * <p>
     * Held in {@link EcCurves} rather than here, because {@code ECAgreementTest}
     * drives the same list and two copies of 82 names drift.
     */
    private static final String[] BUILTIN_CURVES = EcCurves.BUILTIN;

    /**
     * Non-vacuity floors. The sweep skips a curve the build does not serve, so
     * without these a build that served nothing would pass silently. Both were
     * measured well below what a stock 3.5.x build gives (80 and 40).
     */
    private static final int MIN_CURVES_RESOLVED = 40;
    private static final int MIN_PLATFORM_COMPARISONS = 15;

    /** SECG spelling, then the X9.62 name OpenSSL registers the curve under. */
    private static final String[][] SECG_PAIRS = {
            {"secp192r1", "prime192v1"}, {"secp256r1", "prime256v1"}};

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /**
     * The stub-killer: for every curve the platform also knows, our spec must
     * equal its spec field-by-field AND our encoding must be byte-identical.
     * A lookup that ignored its argument would agree on at most one curve.
     */
    @Test
    public void resolvedParametersAgreeWithThePlatformOnEveryCurveBothKnow()
        throws Exception
    {
        int resolved = 0;
        int compared = 0;
        List<String> specMismatch = new ArrayList<String>();
        List<String> encMismatch = new ArrayList<String>();

        for (String curve : BUILTIN_CURVES)
        {
            ECParameterSpec mine = ours(curve);
            if (mine == null)
            {
                continue;
            }
            resolved++;

            ECParameterSpec platform = platform(curve);
            if (platform == null)
            {
                continue;
            }
            compared++;
            if (!sameParameters(mine, platform))
            {
                specMismatch.add(curve);
            }

            byte[] myEncoding = encodedByUs(curve);
            byte[] platformEncoding = encodedByPlatform(curve);
            if (myEncoding != null && platformEncoding != null
                    && !Arrays.areEqual(myEncoding, platformEncoding))
            {
                encMismatch.add(curve);
            }
        }

        Assertions.assertTrue(specMismatch.isEmpty(),
                "domain parameters differ from the platform for: " + specMismatch);
        Assertions.assertTrue(encMismatch.isEmpty(),
                "namedCurve encodings differ from the platform for: " + encMismatch);
        Assertions.assertTrue(resolved >= MIN_CURVES_RESOLVED,
                "only " + resolved + " curves resolved; expected at least "
                        + MIN_CURVES_RESOLVED + " — the sweep has gone vacuous");
        Assertions.assertTrue(compared >= MIN_PLATFORM_COMPARISONS,
                "only " + compared + " curves were compared against the platform; "
                        + "expected at least " + MIN_PLATFORM_COMPARISONS);
    }

    /**
     * The 43. A key that generates must be a key that describes itself: every
     * curve the provider will generate on must answer {@code getParams()}.
     * Counted rather than spot-checked, because the defect this replaced was a
     * count (43 of 82), not a single curve.
     */
    @Test
    public void everyCurveThatGeneratesAKeyAlsoAnswersGetParams() throws Exception
    {
        int generated = 0;
        List<String> failed = new ArrayList<String>();
        for (String curve : BUILTIN_CURVES)
        {
            KeyPair kp;
            try
            {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
                g.initialize(new ECGenParameterSpec(curve));
                kp = g.generateKeyPair();
            }
            catch (Exception notServed)
            {
                continue;
            }
            generated++;
            try
            {
                ECParameterSpec params = ((ECPrivateKey) kp.getPrivate()).getParams();
                Assertions.assertNotNull(params, curve);
            }
            catch (RuntimeException e)
            {
                failed.add(curve + ": " + e.getMessage());
            }
        }
        Assertions.assertTrue(failed.isEmpty(),
                "generated a key whose getParams() failed: " + failed);
        Assertions.assertTrue(generated >= MIN_CURVES_RESOLVED,
                "only " + generated + " curves generated; the sweep has gone vacuous");
    }

    /**
     * The 24: the reverse direction, which the hardcoded candidate list capped.
     * SM2 is excluded because its failure is downstream of the lookup and
     * predates this work — OpenSSL builds an SM2-typed key from those domain
     * parameters, which the EC component path then refuses.
     */
    @Test
    public void everyCurveRebuildsFromItsOwnExplicitParameters() throws Exception
    {
        int rebuilt = 0;
        List<String> failed = new ArrayList<String>();
        for (String curve : BUILTIN_CURVES)
        {
            if ("SM2".equals(curve))
            {
                continue;
            }
            KeyPair kp;
            try
            {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC", jsl);
                g.initialize(new ECGenParameterSpec(curve));
                kp = g.generateKeyPair();
            }
            catch (Exception notServed)
            {
                continue;
            }
            ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
            try
            {
                KeyFactory kf = KeyFactory.getInstance("EC", jsl);
                Assertions.assertNotNull(kf.generatePrivate(
                        new ECPrivateKeySpec(priv.getS(), priv.getParams())), curve);
                rebuilt++;
            }
            catch (Exception e)
            {
                failed.add(curve + ": " + e.getMessage());
            }
        }
        Assertions.assertTrue(failed.isEmpty(),
                "could not rebuild a key from its own parameters: " + failed);
        Assertions.assertTrue(rebuilt >= MIN_CURVES_RESOLVED,
                "only " + rebuilt + " curves rebuilt; the sweep has gone vacuous");
    }

    /**
     * The negative path for the reverse lookup, on a PRIME and a BINARY curve.
     * A stub that named a curve regardless of its input passes every positive
     * test above and fails here.
     */
    @Test
    public void tamperedDomainParametersMatchNoNamedCurve() throws Exception
    {
        for (String curve : new String[]{"prime256v1", "sect233r1"})
        {
            ECParameterSpec real = ours(curve);
            if (real == null)
            {
                continue;
            }
            EllipticCurve tampered = new EllipticCurve(real.getCurve().getField(),
                    real.getCurve().getA(),
                    real.getCurve().getB().add(BigInteger.ONE));
            ECParameterSpec bogus = new ECParameterSpec(tampered, real.getGenerator(),
                    real.getOrder(), real.getCofactor());

            KeyFactory kf = KeyFactory.getInstance("EC", jsl);
            InvalidKeySpecException e = Assertions.assertThrows(
                    InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new ECPrivateKeySpec(BigInteger.valueOf(7), bogus)),
                    curve + " with a tampered b must match no named curve");
            Assertions.assertEquals(
                    "unable to resolve ECParameterSpec to a known OpenSSL curve",
                    e.getMessage());
        }
    }

    /**
     * A generator point that is not on the curve names nothing either — the
     * whole domain is compared, not just the coefficients.
     */
    @Test
    public void aGeneratorOffTheCurveMatchesNoNamedCurve() throws Exception
    {
        ECParameterSpec real = ours("prime256v1");
        Assertions.assertNotNull(real);
        ECParameterSpec bogus = new ECParameterSpec(real.getCurve(),
                new ECPoint(real.getGenerator().getAffineX().add(BigInteger.ONE),
                        real.getGenerator().getAffineY()),
                real.getOrder(), real.getCofactor());

        KeyFactory kf = KeyFactory.getInstance("EC", jsl);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePrivate(new ECPrivateKeySpec(BigInteger.valueOf(7), bogus)));
        Assertions.assertEquals(
                "unable to resolve ECParameterSpec to a known OpenSSL curve", e.getMessage());
    }

    /**
     * Both directions of the two-entry SECG substitution table, per curve:
     * the SECG spelling must go IN, and must come back OUT of
     * {@code getParameterSpec(ECGenParameterSpec.class)} so the answer matches
     * what the platform gives for the same curve.
     */
    @Test
    public void theTwoSecgSpellingsWorkInBothDirections() throws Exception
    {
        for (String[] pair : SECG_PAIRS)
        {
            String secg = pair[0];
            String openssl = pair[1];

            ECParameterSpec viaSecg = ours(secg);
            ECParameterSpec viaOpenSsl = ours(openssl);
            if (viaOpenSsl == null)
            {
                continue;
            }
            Assertions.assertNotNull(viaSecg, secg + " must resolve through the substitution");
            Assertions.assertTrue(sameParameters(viaSecg, viaOpenSsl),
                    secg + " and " + openssl + " must describe the same curve");

            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", jsl);
            ap.init(new ECGenParameterSpec(openssl));
            Assertions.assertEquals(secg,
                    ap.getParameterSpec(ECGenParameterSpec.class).getName(),
                    "the SECG spelling is what a JCE caller expects back");
        }
    }

    /**
     * Vacuity guard for the substitution table: it exists only because OpenSSL
     * resolves neither SECG spelling. If a future OpenSSL learns them the
     * entries become dead code, and this fails by name rather than letting the
     * carve-out outlive its reason.
     *
     * <p><b>Asked at the NI, deliberately.</b> The provider-level form of this
     * question cannot answer it. OpenSSL can learn a name in two ways: as a new
     * canonical short name, or — far more likely — as an ALIAS onto the
     * existing NID. Under the alias form {@code OBJ_txt2nid} resolves,
     * canonicalisation returns {@code prime256v1} exactly as the substitution
     * would, and every provider-level observation is unchanged. Only asking the
     * curve table directly separates "OpenSSL does not know this name" from
     * "our table silently supplied it".
     */
    @Test
    public void theSecgSubstitutionsAreStillNeeded()
    {
        ECServiceNI ni = TestNISelector.getECNi();
        for (String[] pair : SECG_PAIRS)
        {
            if (ni.getCurveComponent(pair[1], ECServiceNI.CURVE_COMP_NAME, null) < 0)
            {
                continue;
            }
            Assertions.assertEquals(ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode(),
                    ni.getCurveComponent(pair[0], ECServiceNI.CURVE_COMP_NAME, null),
                    pair[0] + " now resolves natively — OpenSSL has learned it, so the "
                            + "SECG substitution entry is dead code and must be dropped");
        }
    }

    /**
     * The other half: the substitution must actually WORK. Kept separate from
     * the vacuity guard above so a failure says which of the two properties
     * broke — the table being unnecessary, or the table not being applied.
     */
    @Test
    public void theSecgSubstitutionsResolveThroughTheProvider() throws Exception
    {
        for (String[] pair : SECG_PAIRS)
        {
            if (ours(pair[1]) == null)
            {
                continue;
            }
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", jsl);
            ap.init(new ECGenParameterSpec(pair[0]));
            Assertions.assertEquals(pair[1], ap.toString(),
                    pair[0] + " must reach " + pair[1] + " through the substitution");
        }
    }

    /**
     * Curve names arrive in four spellings and all must reach the same curve.
     * The OID form is the one that cannot work without canonicalisation:
     * {@code OSSL_PKEY_PARAM_GROUP_NAME} does not accept dotted OIDs.
     */
    @Test
    public void everySpellingOfACurveResolvesToTheSameParameters() throws Exception
    {
        String[] spellings = {"prime256v1", "P-256", "secp256r1", "1.2.840.10045.3.1.7"};
        ECParameterSpec first = null;
        for (String spelling : spellings)
        {
            ECParameterSpec spec = ours(spelling);
            Assertions.assertNotNull(spec, spelling + " must resolve");
            if (first == null)
            {
                first = spec;
            }
            else
            {
                Assertions.assertTrue(sameParameters(first, spec),
                        spelling + " must describe the same curve as " + spellings[0]);
            }
        }
    }

    /** A zero coefficient is a real case, not a theoretical one: secp256k1 has a == 0. */
    @Test
    public void aZeroCurveCoefficientSurvivesTheComponentProtocol() throws Exception
    {
        ECParameterSpec spec = ours("secp256k1");
        if (spec == null)
        {
            return;
        }
        Assertions.assertEquals(BigInteger.ZERO, spec.getCurve().getA(),
                "secp256k1's a is zero, which crosses the bridge as a zero-length component");
        Assertions.assertEquals(BigInteger.valueOf(7), spec.getCurve().getB());
    }

    /** Binary-field curves carry an ECFieldF2m whose mid-terms match the platform's. */
    @Test
    public void binaryCurvesCarryAnF2mFieldWithPlatformMatchingMidTerms() throws Exception
    {
        int checked = 0;
        for (String curve : new String[]{"sect163k1", "sect233r1", "sect571r1"})
        {
            ECParameterSpec mine = ours(curve);
            ECParameterSpec platform = platform(curve);
            if (mine == null || platform == null)
            {
                continue;
            }
            Assertions.assertTrue(mine.getCurve().getField() instanceof ECFieldF2m, curve);
            ECFieldF2m a = (ECFieldF2m) mine.getCurve().getField();
            ECFieldF2m b = (ECFieldF2m) platform.getCurve().getField();
            Assertions.assertEquals(b.getM(), a.getM(), curve);
            Assertions.assertArrayEquals(b.getMidTermsOfReductionPolynomial(),
                    a.getMidTermsOfReductionPolynomial(), curve);
            checked++;
        }
        Assertions.assertTrue(checked > 0,
                "no binary curve was available to check — this build has no ec2m support, "
                        + "so state that rather than passing silently");
    }

    /** Prime curves carry ECFieldFp with OpenSSL's own p. */
    @Test
    public void primeCurvesCarryAnFpFieldMatchingThePlatform() throws Exception
    {
        ECParameterSpec mine = ours("prime256v1");
        ECParameterSpec platform = platform("prime256v1");
        Assertions.assertNotNull(mine);
        Assertions.assertNotNull(platform);
        Assertions.assertTrue(mine.getCurve().getField() instanceof ECFieldFp);
        Assertions.assertEquals(((ECFieldFp) platform.getCurve().getField()).getP(),
                ((ECFieldFp) mine.getCurve().getField()).getP());
    }

    /**
     * The AlgorithmParameters service answers from this provider, not from
     * whatever else is installed. Registration is not the property being
     * tested — the property is that the ANSWER is ours, which a delegating
     * implementation would also satisfy, so it is paired with the
     * platform-comparison sweep above rather than standing alone.
     */
    @Test
    public void theEcAlgorithmParametersServiceIsServedByThisProvider() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", jsl);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, ap.getProvider().getName());
        ap.init(new ECGenParameterSpec("prime256v1"));
        Assertions.assertEquals("06082A8648CE3D030107", hex(ap.getEncoded()),
                "the namedCurve encoding of prime256v1 is fixed by X9.62");
    }

    /** Encode then decode must land on the same curve. */
    @Test
    public void namedCurveEncodingsRoundTrip() throws Exception
    {
        int checked = 0;
        for (String curve : BUILTIN_CURVES)
        {
            byte[] encoded = encodedByUs(curve);
            if (encoded == null)
            {
                continue;
            }
            AlgorithmParameters back = AlgorithmParameters.getInstance("EC", jsl);
            back.init(encoded);
            Assertions.assertTrue(
                    sameParameters(ours(curve), back.getParameterSpec(ECParameterSpec.class)),
                    curve + " must survive an encode / decode round trip");
            checked++;
        }
        Assertions.assertTrue(checked >= MIN_CURVES_RESOLVED,
                "only " + checked + " curves round-tripped; the sweep has gone vacuous");
    }

    /**
     * The two builtin curves with no object identifier resolve parameters but
     * cannot be encoded as a named curve. Pinned so the failure stays a named
     * refusal rather than becoming a malformed encoding.
     */
    @Test
    public void aCurveWithNoObjectIdentifierRefusesToEncode() throws Exception
    {
        int checked = 0;
        for (String curve : new String[]{"Oakley-EC2N-3", "Oakley-EC2N-4"})
        {
            AlgorithmParameters ap;
            try
            {
                ap = AlgorithmParameters.getInstance("EC", jsl);
                ap.init(new ECGenParameterSpec(curve));
            }
            catch (Exception notServed)
            {
                continue;
            }
            Assertions.assertNotNull(ap.getParameterSpec(ECParameterSpec.class),
                    curve + " must still describe itself");
            java.io.IOException e = Assertions.assertThrows(java.io.IOException.class,
                    ap::getEncoded, curve + " has no OID and must refuse to encode");
            Assertions.assertTrue(e.getMessage().contains("has no object identifier"),
                    "expected a message naming the cause, got: " + e.getMessage());
            checked++;
        }
        Assertions.assertTrue(checked > 0, "neither Oakley curve was available");
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static ECParameterSpec ours(String curve)
    {
        try
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", jsl);
            ap.init(new ECGenParameterSpec(curve));
            return ap.getParameterSpec(ECParameterSpec.class);
        }
        catch (Exception notServed)
        {
            return null;
        }
    }

    private static byte[] encodedByUs(String curve)
    {
        try
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", jsl);
            ap.init(new ECGenParameterSpec(curve));
            return ap.getEncoded();
        }
        catch (Exception notServed)
        {
            return null;
        }
    }

    private static ECParameterSpec platform(String curve)
    {
        for (String alias : new String[]{curve, secgSpelling(curve)})
        {
            if (alias == null)
            {
                continue;
            }
            try
            {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", "SunEC");
                ap.init(new ECGenParameterSpec(alias));
                return ap.getParameterSpec(ECParameterSpec.class);
            }
            catch (Exception notKnown)
            {
                // try the next spelling
            }
        }
        return null;
    }

    private static byte[] encodedByPlatform(String curve)
    {
        for (String alias : new String[]{curve, secgSpelling(curve)})
        {
            if (alias == null)
            {
                continue;
            }
            try
            {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", "SunEC");
                ap.init(new ECGenParameterSpec(alias));
                return ap.getEncoded();
            }
            catch (Exception notKnown)
            {
                // try the next spelling
            }
        }
        return null;
    }

    /** SunEC knows these two curves only under their SECG names. */
    private static String secgSpelling(String openSslName)
    {
        if ("prime256v1".equals(openSslName))
        {
            return "secp256r1";
        }
        if ("prime192v1".equals(openSslName))
        {
            return "secp192r1";
        }
        return null;
    }

    private static boolean sameParameters(ECParameterSpec a, ECParameterSpec b)
    {
        return a != null && b != null
                && a.getCofactor() == b.getCofactor()
                && a.getOrder().equals(b.getOrder())
                && a.getCurve().equals(b.getCurve())
                && a.getGenerator().equals(b.getGenerator());
    }

    private static String hex(byte[] value)
    {
        StringBuilder sb = new StringBuilder(value.length * 2);
        for (int i = 0; i != value.length; i++)
        {
            sb.append(String.format("%02X", value[i]));
        }
        return sb.toString();
    }
}
