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

package org.openssl.jostle.test.certpath;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Certification path building and validation, ours against BouncyCastle, over
 * the {@link BcBuiltChains} corpus.
 *
 * <p><b>Scope, and what this deliberately does NOT do.</b> Every PKITS row is
 * already asserted against its specification outcome on this provider, on SUN
 * and on BouncyCastle by {@link PkitsThreeWayTest}; re-asserting those rows
 * here would duplicate a measurement rather than add one. This class covers
 * what PKITS cannot reach: PKITS is entirely RSA, so the post-quantum,
 * Edwards and elliptic-curve paths have no corpus at all, and PKITS carries
 * no policy mapping, no name-constraint pair, no path-length boundary and no
 * critical extension of our choosing.
 *
 * <p>BouncyCastle mints this corpus and is also the reference for it — stated
 * in {@link BcBuiltChains} and repeated once here, because a defect the two
 * of us share is invisible to every cell below. PKITS remains the corpus with
 * outcomes that are not another implementation's opinion.
 *
 * <p><b>Three divergences are pinned in BOTH halves</b>, so each fails as
 * loudly if BouncyCastle moves toward us as if we drift toward it: the DSA
 * parameter inheritance refusal, the notAfter boundary, and policy
 * processing. A pin reading only "we differ" is satisfied by the difference
 * reversing.
 */
public class CertPathAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String SUN = "SUN";

    /**
     * Shapes on which the two providers are MEASURED to disagree, so the
     * agreement sweep must skip them and a named cell must pin them. An entry
     * here that starts agreeing is caught by
     * {@link #everyPinnedDivergenceIsStillEarnt}.
     */
    private static final Set<String> PINNED_DIVERGENCES =
            new TreeSet<String>(java.util.Arrays.asList("dsa-inherited-parameters"));

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

    // -----------------------------------------------------------------
    // (a) the verdict, us against BouncyCastle
    // -----------------------------------------------------------------

    /**
     * Every key family: a clean path validates on both, a revoked end entity
     * is refused by both, and an end entity whose subject was altered after
     * signing is refused by both.
     * <p>
     * The tampered certificate still decodes — one byte of the subject
     * changed, the DER length untouched — so only the signature check can
     * reject it. A certificate refused because it will not parse would
     * measure the decoder instead.
     */
    @Test
    public void everyKeyFamilyAgreesOnTheCleanRevokedAndTamperedVerdicts() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int checked = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            Verdict cleanOurs = validate(JSL, f.root, f.chain(), f.crls(), null);
            Verdict cleanTheirs = validate(BC, f.root, f.chain(), f.crls(), null);
            agree(bad, f.label + " clean", cleanOurs, cleanTheirs);
            note(bad, f.label + " clean must validate", cleanOurs.valid);

            Verdict revokedOurs = validate(JSL, f.root, f.chainTo(f.revokedEe), f.crls(), null);
            Verdict revokedTheirs = validate(BC, f.root, f.chainTo(f.revokedEe), f.crls(), null);
            agree(bad, f.label + " revoked", revokedOurs, revokedTheirs);
            note(bad, f.label + " revoked must be refused", !revokedOurs.valid);

            Verdict tamperedOurs = validate(JSL, f.root, f.chainTo(f.tamperedEe), f.crls(), null);
            Verdict tamperedTheirs = validate(BC, f.root, f.chainTo(f.tamperedEe), f.crls(), null);
            agree(bad, f.label + " tampered", tamperedOurs, tamperedTheirs);
            note(bad, f.label + " tampered must be refused", !tamperedOurs.valid);

            checked++;
        }

        Assertions.assertEquals(13, checked,
                "the corpus no longer carries thirteen key families");
        Assertions.assertTrue(bad.isEmpty(), report(bad));
    }

    /**
     * Every shape PKITS does not carry, except those pinned as divergent.
     * The verdict must agree; the MESSAGES need not, and are not compared —
     * two implementations may refuse the same path for reasons they describe
     * differently without either being wrong.
     */
    @Test
    public void everyShapeAgreesOnTheVerdictExceptWherePinned() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int checked = 0;
        Set<String> seen = new TreeSet<String>();

        for (BcBuiltChains.Shape s : BcBuiltChains.shapes())
        {
            seen.add(s.label);
            if (PINNED_DIVERGENCES.contains(s.label))
            {
                continue;
            }
            agree(bad, s.label,
                    validate(JSL, s.root, s.chain, s.crls, s.validAt),
                    validate(BC, s.root, s.chain, s.crls, s.validAt));
            checked++;
        }

        Assertions.assertTrue(seen.containsAll(PINNED_DIVERGENCES),
                "a pinned divergence names a shape the corpus does not carry: "
                        + PINNED_DIVERGENCES + " against " + seen);
        Assertions.assertTrue(checked >= 8,
                "only " + checked + " shapes were compared — the corpus has been hollowed out");
        Assertions.assertTrue(bad.isEmpty(), report(bad));
    }

    /**
     * The corpus discriminates. At least one shape must be refused and at
     * least one accepted, or the sweep above would pass on a validator that
     * answered the same thing every time.
     */
    @Test
    public void theCorpusSeparatesAcceptanceFromRefusal() throws Exception
    {
        int accepted = 0;
        int refused = 0;
        for (BcBuiltChains.Shape s : BcBuiltChains.shapes())
        {
            if (validate(JSL, s.root, s.chain, s.crls, s.validAt).valid)
            {
                accepted++;
            }
            else
            {
                refused++;
            }
        }
        Assertions.assertTrue(accepted > 0, "no shape validates; the corpus cannot discriminate");
        Assertions.assertTrue(refused > 0, "no shape is refused; the corpus cannot discriminate");
    }

    // -----------------------------------------------------------------
    // (a) the pinned divergences, both halves
    // -----------------------------------------------------------------

    /**
     * RFC 3279 §2.3.2 DSA parameter inheritance. An end entity whose
     * SubjectPublicKeyInfo omits the DSA parameters and takes them from its
     * issuer is refused by us and validated by BouncyCastle.
     * <p>
     * Independent of PKITS, which carries two such certificates and sanctions
     * the same refusal as row 4.1.5 — this one is minted here, so the
     * divergence is measured twice from unrelated material rather than
     * inherited from one corpus.
     */
    @Test
    public void theDsaParameterInheritanceDivergenceIsPinnedInBothHalves() throws Exception
    {
        BcBuiltChains.Shape s = BcBuiltChains.shape("dsa-inherited-parameters");
        Verdict ours = validate(JSL, s.root, s.chain, s.crls, null);
        Verdict theirs = validate(BC, s.root, s.chain, s.crls, null);

        Assertions.assertAll(
                () -> Assertions.assertFalse(ours.valid,
                        "we now validate a DSA key that inherits its parameters — this pin is stale"),
                () -> Assertions.assertTrue(theirs.valid,
                        "BouncyCastle now refuses the inherited-parameter path too — this pin is stale"));
    }

    /**
     * The validity boundary. RFC 5280 §4.1.2.5 defines the period as "from
     * notBefore through notAfter, inclusive" (RFC-5280.txt:1214-1215, sha256
     * a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d in the
     * standards library index).
     * <p>
     * notBefore is inclusive here and everywhere. notAfter is not: OpenSSL's
     * {@code X509_cmp_time} returns -1 when the certificate time is "earlier
     * than, or equal to" the reference time (doc/man3/X509_cmp_time.pod), and
     * {@code ossl_x509_check_cert_time} raises the expired error on that
     * value, so equality reads as expired at one end and valid at the other.
     * A certificate is therefore refused for the final second of its stated
     * validity. Reported upstream in
     * reviews/openssl-notafter-boundary-report-2026-09-19.md.
     * <p>
     * Four answers are pinned, not one, because the disagreement is INTERNAL
     * as well as external: our own {@code checkValidity} accepts the instant
     * our path validator rejects. A change on any of the four sides must
     * report here.
     */
    @Test
    public void theNotAfterBoundaryIsPinnedOnAllFourAnswers() throws Exception
    {
        BcBuiltChains.Shape s = BcBuiltChains.shape("validity-boundary");
        X509Certificate ee = s.endEntity();
        Date notBefore = ee.getNotBefore();
        Date notAfter = ee.getNotAfter();

        // The inclusive end that everybody agrees on, first: without it a
        // validator refusing every date would satisfy the notAfter half.
        Assertions.assertAll(
                () -> Assertions.assertTrue(validate(JSL, s.root, s.chain, s.crls, notBefore).valid,
                        "we refuse the certificate at exactly notBefore"),
                () -> Assertions.assertTrue(validate(BC, s.root, s.chain, s.crls, notBefore).valid,
                        "BouncyCastle refuses the certificate at exactly notBefore"),
                () -> Assertions.assertTrue(validate(SUN, s.root, s.chain, s.crls, notBefore).valid,
                        "SUN refuses the certificate at exactly notBefore"),
                () -> Assertions.assertFalse(
                        validate(JSL, s.root, s.chain, s.crls, before(notBefore)).valid,
                        "we accept the certificate one second before notBefore"));

        // One second inside notAfter, so the boundary cell below is known to
        // sit on the boundary rather than inside an already-expired window.
        Assertions.assertTrue(validate(JSL, s.root, s.chain, s.crls, before(notAfter)).valid,
                "we refuse the certificate a second before notAfter, so the pin below "
                        + "is not measuring the boundary");

        Verdict oursAt = validate(JSL, s.root, s.chain, s.crls, notAfter);
        Assertions.assertAll(
                () -> Assertions.assertFalse(oursAt.valid,
                        "our path validator now accepts the instant notAfter — this pin is stale"),
                () -> Assertions.assertTrue(oursAt.message.contains("certificate has expired"),
                        "the refusal is no longer the expired error: " + oursAt.message),
                () -> Assertions.assertTrue(validate(BC, s.root, s.chain, s.crls, notAfter).valid,
                        "BouncyCastle now refuses at notAfter — this pin is stale"),
                () -> Assertions.assertTrue(validate(SUN, s.root, s.chain, s.crls, notAfter).valid,
                        "SUN now refuses at notAfter — this pin is stale"),
                // The internal half: the same provider, the same certificate,
                // the same instant, the other surface.
                () -> ours(ee).checkValidity(notAfter),
                () -> Assertions.assertFalse(
                        validate(JSL, s.root, s.chain, s.crls, after(notAfter)).valid,
                        "we accept the certificate one second after notAfter"));
    }

    // -----------------------------------------------------------------
    // (b) the BUILT path
    // -----------------------------------------------------------------

    /**
     * The path we BUILD, against the path BouncyCastle builds from the same
     * pool: the same certificates, in the same order, by encoding.
     * <p>
     * Compared by encoding rather than by {@code equals}: our certificate
     * class delegates equality, so an {@code assertEquals} between a
     * BouncyCastle certificate and ours passes whoever decoded it and would
     * be blind to the provenance the cell exists to measure. The length is
     * asserted separately from the contents so a truncated path names itself.
     */
    @Test
    public void theBuiltPathMatchesTheOneBouncyCastleBuilds() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int built = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            List<? extends Certificate> ours = build(JSL, f);
            List<? extends Certificate> theirs = build(BC, f);

            if (ours.size() != theirs.size())
            {
                bad.add(f.label + " :: path length " + ours.size() + " against " + theirs.size());
                continue;
            }
            // The path is the chain below the anchor: the end entity and the
            // intermediate, the root being the anchor rather than a member.
            if (ours.size() != 2)
            {
                bad.add(f.label + " :: built " + ours.size() + " certificates, expected 2");
                continue;
            }
            for (int i = 0; i < ours.size(); i++)
            {
                if (!Arrays.areEqual(ours.get(i).getEncoded(), theirs.get(i).getEncoded()))
                {
                    bad.add(f.label + " :: certificate " + i + " differs from BouncyCastle's");
                }
            }
            if (!Arrays.areEqual(ours.get(0).getEncoded(), f.ee.getEncoded()))
            {
                bad.add(f.label + " :: the built path does not start at the requested target");
            }
            built++;
        }

        Assertions.assertEquals(13, built, "not every family produced a built path");
        Assertions.assertTrue(bad.isEmpty(), report(bad));
    }

    // -----------------------------------------------------------------
    // (c) the validator RESULT
    // -----------------------------------------------------------------

    /**
     * The result content: the trust anchor and the subject public key.
     * <p>
     * The anchor is compared by its certificate's encoding and the key by its
     * own encoding, for the same reason the built path is — an
     * {@code assertEquals} on either would be satisfied by value equality
     * regardless of which provider produced the object.
     */
    @Test
    public void theValidatorResultAgreesOnTheAnchorAndTheSubjectPublicKey() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int compared = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            PKIXCertPathValidatorResult ours = result(JSL, f);
            PKIXCertPathValidatorResult theirs = result(BC, f);

            byte[] ourAnchor = ours.getTrustAnchor().getTrustedCert().getEncoded();
            byte[] theirAnchor = theirs.getTrustAnchor().getTrustedCert().getEncoded();
            if (!Arrays.areEqual(ourAnchor, theirAnchor))
            {
                bad.add(f.label + " :: trust anchor differs");
            }
            if (!Arrays.areEqual(ourAnchor, f.root.getEncoded()))
            {
                bad.add(f.label + " :: the reported anchor is not the root we supplied");
            }

            PublicKey ourKey = ours.getPublicKey();
            PublicKey theirKey = theirs.getPublicKey();
            if (!Arrays.areEqual(ourKey.getEncoded(), theirKey.getEncoded()))
            {
                bad.add(f.label + " :: subject public key encoding differs");
            }
            if (!Arrays.areEqual(ourKey.getEncoded(), f.ee.getPublicKey().getEncoded()))
            {
                bad.add(f.label + " :: the reported key is not the end entity's");
            }
            compared++;
        }

        Assertions.assertEquals(13, compared, "not every family produced a result");
        Assertions.assertTrue(bad.isEmpty(), report(bad));
    }

    /**
     * The policy tree, pinned in both halves.
     * <p>
     * This provider does no policy processing and says so: the result's
     * policy tree is always null, because a fabricated tree would be worse
     * than none. So there is nothing to compare, and the cell pins the
     * absence against a reference that does build one — ours null on every
     * family AND on the chain that carries an explicit policy with a mapping,
     * BouncyCastle's non-null on that chain.
     */
    @Test
    public void thePolicyTreeAbsenceIsPinnedInBothHalves() throws Exception
    {
        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            Assertions.assertNull(result(JSL, f).getPolicyTree(),
                    f.label + ": we now report a policy tree, having done no policy processing");
        }

        BcBuiltChains.Shape policy = BcBuiltChains.shape("policy-mapping");
        PKIXCertPathValidatorResult ours = (PKIXCertPathValidatorResult)
                CertPathValidator.getInstance("PKIX", JSL)
                        .validate(path(policy.chain), plain(policy));
        PKIXCertPathValidatorResult theirs = (PKIXCertPathValidatorResult)
                CertPathValidator.getInstance("PKIX", BC)
                        .validate(path(policy.chain), plain(policy));

        Assertions.assertAll(
                () -> Assertions.assertNull(ours.getPolicyTree(),
                        "we now report a policy tree for the explicit-policy chain"),
                () -> Assertions.assertNotNull(theirs.getPolicyTree(),
                        "BouncyCastle no longer builds a policy tree for a chain asserting an "
                                + "explicit policy and a mapping — this pin is stale"));
    }

    /**
     * Asking for policy processing is refused by name, not ignored.
     * <p>
     * Ignoring would return a green result for a check that never ran, which
     * is the failure this provider is built to avoid. Each of the four
     * parameters is pinned by its exact message, because a refusal moving to
     * a different arm keeps the type and changes what the caller is told.
     */
    @Test
    public void everyPolicyParameterIsRefusedByItsOwnMessage() throws Exception
    {
        BcBuiltChains.Shape s = BcBuiltChains.shape("policy-mapping");

        PKIXParameters explicitPolicy = plain(s);
        explicitPolicy.setExplicitPolicyRequired(true);
        refused(explicitPolicy, s,
                "explicit policy is not supported: this provider does no policy processing");

        PKIXParameters mappingInhibited = plain(s);
        mappingInhibited.setPolicyMappingInhibited(true);
        refused(mappingInhibited, s,
                "policy mapping inhibition is not supported: this provider does no policy processing");

        PKIXParameters anyInhibited = plain(s);
        anyInhibited.setAnyPolicyInhibited(true);
        refused(anyInhibited, s,
                "any-policy inhibition is not supported: this provider does no policy processing");

        PKIXParameters initial = plain(s);
        initial.setInitialPolicies(new HashSet<String>(
                Collections.singletonList(BcBuiltChains.POLICY_ASSERTED)));
        refused(initial, s,
                "an initial policy set is not supported: this provider does no policy processing");

        // The control: the same chain with none of them set validates, so the
        // four refusals are attributable to the parameter and not the fixture.
        Assertions.assertTrue(validate(JSL, s.root, s.chain, s.crls, null).valid,
                "the policy chain does not validate without policy parameters, so the "
                        + "refusals above prove nothing about the parameters");
    }

    // -----------------------------------------------------------------
    // (d) the path encodings
    // -----------------------------------------------------------------

    /**
     * Every family's built path, encoded by us and read back by BouncyCastle
     * and the reverse, in both shared encodings, byte-equal both ways.
     * <p>
     * PKITS can only offer RSA here. This carries the Edwards and
     * post-quantum families through PkiPath and PKCS7, where an
     * AlgorithmIdentifier we emit differently would surface as a decode
     * failure at the far end rather than as a wrong answer.
     */
    @Test
    public void everyFamilysPathRoundTripsThroughBouncyCastleInBothEncodings() throws Exception
    {
        CertificateFactory jsl = CertificateFactory.getInstance("X.509", JSL);
        CertificateFactory bc = CertificateFactory.getInstance("X.509", BC);
        List<String> bad = new ArrayList<String>();
        int round = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            List<X509Certificate> certs = f.chain();
            for (String encoding : new String[]{"PkiPath", "PKCS7"})
            {
                byte[] ours = jsl.generateCertPath(certs).getEncoded(encoding);
                byte[] theirs = bc.generateCertPath(certs).getEncoded(encoding);
                if (!Arrays.areEqual(ours, theirs))
                {
                    bad.add(f.label + " :: " + encoding + " :: the two encoders disagree");
                    continue;
                }
                List<? extends Certificate> viaBc = bc.generateCertPath(
                        new ByteArrayInputStream(ours), encoding).getCertificates();
                List<? extends Certificate> viaUs = jsl.generateCertPath(
                        new ByteArrayInputStream(theirs), encoding).getCertificates();
                if (viaBc.size() != certs.size())
                {
                    bad.add(f.label + " :: " + encoding + " :: BouncyCastle read back "
                            + viaBc.size() + " of " + certs.size());
                }
                if (viaUs.size() != certs.size())
                {
                    bad.add(f.label + " :: " + encoding + " :: we read back "
                            + viaUs.size() + " of " + certs.size());
                }
                for (int i = 0; i < Math.min(viaUs.size(), certs.size()); i++)
                {
                    if (!Arrays.areEqual(viaUs.get(i).getEncoded(), certs.get(i).getEncoded()))
                    {
                        bad.add(f.label + " :: " + encoding + " :: certificate " + i
                                + " did not survive the round trip");
                    }
                }
                round++;
            }
        }

        Assertions.assertEquals(26, round, "not every family round-tripped in both encodings");
        Assertions.assertTrue(bad.isEmpty(), report(bad));
    }

    // -----------------------------------------------------------------
    // Staleness
    // -----------------------------------------------------------------

    /**
     * A pinned divergence that starts agreeing must be reported. A silent
     * pass leaves a stale pin indistinguishable from a justified one, and the
     * sweep above SKIPS these shapes, so nothing else would notice.
     */
    @Test
    public void everyPinnedDivergenceIsStillEarnt() throws Exception
    {
        List<String> caughtUp = new ArrayList<String>();
        int checked = 0;
        for (String label : PINNED_DIVERGENCES)
        {
            BcBuiltChains.Shape s = BcBuiltChains.shape(label);
            Verdict ours = validate(JSL, s.root, s.chain, s.crls, s.validAt);
            Verdict theirs = validate(BC, s.root, s.chain, s.crls, s.validAt);
            if (ours.valid == theirs.valid)
            {
                caughtUp.add(label + ": the two providers now agree; remove it from "
                        + "PINNED_DIVERGENCES and let the sweep cover it");
            }
            checked++;
        }
        Assertions.assertTrue(checked > 0, "no pinned divergence was checked");
        Assertions.assertTrue(caughtUp.isEmpty(), caughtUp.toString());
    }

    // -----------------------------------------------------------------

    /** A validation outcome and, when it failed, what was said about it. */
    private static final class Verdict
    {
        final boolean valid;
        final String message;

        Verdict(boolean valid, String message)
        {
            this.valid = valid;
            this.message = message;
        }
    }

    private static Verdict validate(String provider, X509Certificate root,
                                    List<X509Certificate> chain, List<X509CRL> crls, Date when)
            throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", provider)
                    .validate(path(chain), params(root, crls, when));
            return new Verdict(true, null);
        }
        catch (CertPathValidatorException refused)
        {
            return new Verdict(false, String.valueOf(refused.getMessage()));
        }
    }

    private static CertPath path(List<X509Certificate> chain) throws Exception
    {
        return CertificateFactory.getInstance("X.509").generateCertPath(chain);
    }

    private static PKIXParameters params(X509Certificate root, List<X509CRL> crls, Date when)
            throws Exception
    {
        PKIXParameters p = new PKIXParameters(
                Collections.singleton(new TrustAnchor(root, null)));
        p.setRevocationEnabled(true);
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(crls)));
        p.setDate(when == null ? new Date() : when);
        return p;
    }

    private static PKIXParameters plain(BcBuiltChains.Shape s) throws Exception
    {
        return params(s.root, s.crls, s.validAt);
    }

    private static void refused(PKIXParameters p, BcBuiltChains.Shape s, String message)
            throws Exception
    {
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> CertPathValidator.getInstance("PKIX", JSL).validate(path(s.chain), p));
        Assertions.assertEquals(message, e.getMessage());
    }

    private static PKIXCertPathValidatorResult result(String provider, BcBuiltChains.Family f)
            throws Exception
    {
        return (PKIXCertPathValidatorResult) CertPathValidator.getInstance("PKIX", provider)
                .validate(path(f.chain()), params(f.root, f.crls(), null));
    }

    private static List<? extends Certificate> build(String provider, BcBuiltChains.Family f)
            throws Exception
    {
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(f.ee);
        PKIXBuilderParameters p = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor(f.root, null)), target);
        p.setRevocationEnabled(false);
        List<Object> pool = new ArrayList<Object>();
        pool.add(f.ee);
        pool.add(f.ca);
        p.addCertStore(CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(pool)));
        CertPathBuilderResult r = CertPathBuilder.getInstance("PKIX", provider).build(p);
        return r.getCertPath().getCertificates();
    }

    /** The certificate as OUR factory decodes it, whoever minted the bytes. */
    private static X509Certificate ours(X509Certificate any) throws Exception
    {
        return (X509Certificate) CertificateFactory.getInstance("X.509", JSL)
                .generateCertificate(new ByteArrayInputStream(any.getEncoded()));
    }

    private static Date before(Date d)
    {
        return new Date(d.getTime() - 1000L);
    }

    private static Date after(Date d)
    {
        return new Date(d.getTime() + 1000L);
    }

    private static void agree(List<String> bad, String what, Verdict ours, Verdict theirs)
    {
        if (ours.valid != theirs.valid)
        {
            bad.add(what + " :: we say " + (ours.valid ? "valid" : "invalid")
                    + " and BouncyCastle says " + (theirs.valid ? "valid" : "invalid")
                    + " [ours: " + ours.message + "] [theirs: " + theirs.message + "]");
        }
    }

    private static void note(List<String> bad, String what, boolean ok)
    {
        if (!ok)
        {
            bad.add(what);
        }
    }

    private static String report(List<String> bad)
    {
        return bad.size() + " disagreements with BouncyCastle:\n  "
                + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 40)));
    }
}
