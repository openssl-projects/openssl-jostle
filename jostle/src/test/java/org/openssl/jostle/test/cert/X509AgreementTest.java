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

package org.openssl.jostle.test.cert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.certpath.BcBuiltChains;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Every X.509 accessor, ours against BouncyCastle's, over the whole PKITS
 * corpus.
 * <p>
 * <b>Why BouncyCastle and not SUN.</b> {@code X509Certificate} and
 * {@code X509CRL} carry CONCRETE accessors that re-parse the encoding through
 * {@code sun.security.x509}; a sweep comparing an inherited one against SUN's
 * compares SUN's parser with itself and is green by construction. The
 * comparison is only a comparison when the two sides have different sources,
 * so the reference here is an independent implementation.
 * {@code X509CertificateFactoryTest.crlEntryRevocationReason_agreesWithSunAcrossTheCorpus}
 * keeps the SUN column; this adds the one it cannot provide.
 * <p>
 * <b>Where we diverge, BOTH halves are pinned.</b> On the thirteen accessors
 * measured over PKITS, where SUN and BouncyCastle disagree this provider
 * answers as SUN does. That rule is bounded by those thirteen: a split found
 * anywhere else takes the answer the specification supports and is pinned on
 * all three providers instead — see
 * {@link #theUnsupportedCriticalExtensionAnswersArePinnedOnAllThree}. A pin reading "differs from BC" is satisfied by the difference
 * REVERSING, so each cell asserts our form AND BouncyCastle's measured form:
 * it must fail as loudly if BouncyCastle moves toward us as if we drift toward
 * it. The measured counts are asserted for the same reason — a change in HOW
 * MANY certificates diverge is a change worth seeing.
 * <p>
 * Ordering is not divergence: {@code getRevokedCertificates} returns a Set, so
 * entries are compared as sets and either implementation may choose an order.
 * <p>
 * <b>Two corpora, for different reasons.</b> PKITS is the fixed-expectation
 * one: its files come with outcomes the specification states, so a provider
 * is measured against something that is not another implementation. It is
 * also entirely RSA, and carries exactly one certificate with a critical
 * extension outside the supported set. {@link BcBuiltChains} supplies the
 * reach it lacks — the elliptic-curve, Edwards and post-quantum families, and
 * certificate shapes minted to separate answers the corpus cannot. On that
 * material BouncyCastle is producer AND reference, so a defect the two of us
 * share is invisible there; that is why it supplements PKITS rather than
 * replacing it.
 */
public class X509AgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * The certificates whose DSA public key inherits its parameters from the
     * issuer (RFC 3279 2.3.2), which we refuse to build from the certificate
     * alone and BouncyCastle does not. Pinned BY NAME rather than by count: a
     * count that moved would say the set changed but not which way.
     */
    private static final Set<String> DSA_INHERITED_PARAMETERS =
            new TreeSet<String>(java.util.Arrays.asList(
                    "DSAParametersInheritedCACert.crt",
                    "ValidDSAParameterInheritanceTest5EE.crt"));

    private static CertificateFactory jsl;
    private static CertificateFactory bc;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        jsl = CertificateFactory.getInstance("X.509", JSL);
        bc = CertificateFactory.getInstance("X.509", BC);
        Assertions.assertEquals(BC, bc.getProvider().getName(),
                "the reference factory did not come from BouncyCastle");
    }

    /** The corpus directory, wherever the leg's working directory puts it. */
    private static File corpus(String leaf)
    {
        File dir = new File("src/test/resources/pkits/" + leaf);
        if (!dir.isDirectory())
        {
            dir = new File("jostle/src/test/resources/pkits/" + leaf);
        }
        Assertions.assertTrue(dir.isDirectory(), "PKITS corpus not found at " + dir);
        return dir;
    }

    private static byte[] read(File f) throws Exception
    {
        return java.nio.file.Files.readAllBytes(f.toPath());
    }

    // -----------------------------------------------------------------
    // The agreeing accessors
    // -----------------------------------------------------------------

    /**
     * The accessors that must answer identically. Failures are collected and
     * reported together, so one divergent certificate does not hide the rest.
     */
    @Test
    public void everyCertificateAccessorAgreesWithBouncyCastle() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int compared = 0;
        Set<String> inherited = new TreeSet<String>();

        for (File f : corpus("certs").listFiles())
        {
            byte[] der = read(f);
            X509Certificate ours;
            X509Certificate theirs;
            try
            {
                ours = (X509Certificate) jsl.generateCertificate(new ByteArrayInputStream(der));
                theirs = (X509Certificate) bc.generateCertificate(new ByteArrayInputStream(der));
            }
            catch (Exception notACertificate)
            {
                continue;
            }
            compared++;
            String n = f.getName();

            check(bad, n, "getEncoded", Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()));
            check(bad, n, "getTBSCertificate",
                    Arrays.areEqual(ours.getTBSCertificate(), theirs.getTBSCertificate()));
            check(bad, n, "getSerialNumber", ours.getSerialNumber().equals(theirs.getSerialNumber()));
            check(bad, n, "getVersion", ours.getVersion() == theirs.getVersion());
            check(bad, n, "getNotBefore", ours.getNotBefore().equals(theirs.getNotBefore()));
            check(bad, n, "getNotAfter", ours.getNotAfter().equals(theirs.getNotAfter()));
            check(bad, n, "getIssuerX500Principal",
                    ours.getIssuerX500Principal().equals(theirs.getIssuerX500Principal()));
            check(bad, n, "getSubjectX500Principal",
                    ours.getSubjectX500Principal().equals(theirs.getSubjectX500Principal()));
            check(bad, n, "getSigAlgOID", ours.getSigAlgOID().equals(theirs.getSigAlgOID()));
            check(bad, n, "getBasicConstraints",
                    ours.getBasicConstraints() == theirs.getBasicConstraints());
            check(bad, n, "getKeyUsage",
                    java.util.Arrays.equals(ours.getKeyUsage(), theirs.getKeyUsage()));
            check(bad, n, "getCriticalExtensionOIDs",
                    sorted(ours.getCriticalExtensionOIDs()).equals(sorted(theirs.getCriticalExtensionOIDs())));
            check(bad, n, "getNonCriticalExtensionOIDs",
                    sorted(ours.getNonCriticalExtensionOIDs())
                            .equals(sorted(theirs.getNonCriticalExtensionOIDs())));
            check(bad, n, "hasUnsupportedCriticalExtension",
                    ours.hasUnsupportedCriticalExtension() == theirs.hasUnsupportedCriticalExtension());
            // DSA parameter inheritance from the issuer (RFC 3279 2.3.2) is a
            // known, pinned divergence: we refuse to build such a key from the
            // certificate alone and BouncyCastle does not. Counted rather than
            // skipped, and the count asserted below, so a change in how many
            // certificates take that path is visible here.
            try
            {
                check(bad, n, "getPublicKey.getEncoded",
                        Arrays.areEqual(ours.getPublicKey().getEncoded(),
                                theirs.getPublicKey().getEncoded()));
            }
            catch (java.security.ProviderException inheritsParameters)
            {
                Assertions.assertTrue(inheritsParameters.getMessage()
                                .startsWith("DSA public key inherits its parameters from the issuer"),
                        n + ": unexpected ProviderException from getPublicKey: "
                                + inheritsParameters.getMessage());
                Assertions.assertNotNull(theirs.getPublicKey(),
                        n + ": BouncyCastle now refuses the inherited-parameter key too — "
                                + "the divergence pinned in PkitsDivergenceTest is stale");
                inherited.add(n);
            }

            for (String oid : sorted(ours.getCriticalExtensionOIDs()))
            {
                check(bad, n, "getExtensionValue " + oid,
                        Arrays.areEqual(ours.getExtensionValue(oid), theirs.getExtensionValue(oid)));
            }
            for (String oid : sorted(ours.getNonCriticalExtensionOIDs()))
            {
                check(bad, n, "getExtensionValue " + oid,
                        Arrays.areEqual(ours.getExtensionValue(oid), theirs.getExtensionValue(oid)));
            }
        }

        Assertions.assertTrue(compared > 300,
                "only " + compared + " certificates were compared — the corpus is not being read");
        Assertions.assertEquals(DSA_INHERITED_PARAMETERS, inherited,
                "the set of certificates whose DSA key inherits its parameters from the issuer has "
                        + "moved; a name that left means we now build that key, a name that joined "
                        + "means we stopped");
        Assertions.assertTrue(bad.isEmpty(),
                bad.size() + " accessor disagreements with BouncyCastle:\n  "
                        + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 40))));
        System.out.println("X509AgreementTest: " + compared + " certificates compared, "
                + inherited.size() + " with inherited DSA parameters " + inherited);
    }

    /**
     * The CRL accessors, with revoked entries compared as SETS — the JCA
     * returns a Set and the order is unspecified, so an ordering difference is
     * not a divergence and must not read as one.
     */
    @Test
    public void everyCrlAccessorAgreesWithBouncyCastle() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int compared = 0;

        for (File f : corpus("crls").listFiles())
        {
            byte[] der = read(f);
            X509CRL ours;
            X509CRL theirs;
            try
            {
                ours = (X509CRL) jsl.generateCRL(new ByteArrayInputStream(der));
                theirs = (X509CRL) bc.generateCRL(new ByteArrayInputStream(der));
            }
            catch (Exception notACrl)
            {
                continue;
            }
            compared++;
            String n = f.getName();

            check(bad, n, "getEncoded", Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()));
            check(bad, n, "getTBSCertList",
                    Arrays.areEqual(ours.getTBSCertList(), theirs.getTBSCertList()));
            check(bad, n, "getIssuerX500Principal",
                    ours.getIssuerX500Principal().equals(theirs.getIssuerX500Principal()));
            check(bad, n, "getThisUpdate", ours.getThisUpdate().equals(theirs.getThisUpdate()));
            check(bad, n, "getNextUpdate", ours.getNextUpdate() == null
                    ? theirs.getNextUpdate() == null
                    : ours.getNextUpdate().equals(theirs.getNextUpdate()));
            check(bad, n, "getSigAlgOID", ours.getSigAlgOID().equals(theirs.getSigAlgOID()));
            check(bad, n, "getCriticalExtensionOIDs",
                    sorted(ours.getCriticalExtensionOIDs()).equals(sorted(theirs.getCriticalExtensionOIDs())));
            check(bad, n, "getNonCriticalExtensionOIDs",
                    sorted(ours.getNonCriticalExtensionOIDs())
                            .equals(sorted(theirs.getNonCriticalExtensionOIDs())));
            check(bad, n, "revoked serials as a SET", serials(ours).equals(serials(theirs)));

            Set<? extends X509CRLEntry> theirEntries = theirs.getRevokedCertificates();
            if (theirEntries != null)
            {
                for (X509CRLEntry their : theirEntries)
                {
                    X509CRLEntry our = ours.getRevokedCertificate(their.getSerialNumber());
                    if (our == null)
                    {
                        // An indirect CRL delegates the entry to another issuer,
                        // so the serial-only overload correctly does not find it.
                        continue;
                    }
                    check(bad, n, "entry " + their.getSerialNumber() + " getEncoded",
                            Arrays.areEqual(our.getEncoded(), their.getEncoded()));
                    check(bad, n, "entry " + their.getSerialNumber() + " getRevocationDate",
                            our.getRevocationDate().equals(their.getRevocationDate()));
                }
            }
        }

        Assertions.assertTrue(compared > 100,
                "only " + compared + " CRLs were compared — the corpus is not being read");
        Assertions.assertTrue(bad.isEmpty(),
                bad.size() + " CRL accessor disagreements with BouncyCastle:\n  "
                        + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 40))));
    }

    // -----------------------------------------------------------------
    // The divergences, pinned in both halves
    // -----------------------------------------------------------------

    /**
     * {@code getIssuerDN} / {@code getSubjectDN} have no agreed rendering: the
     * two references disagree on every file, in ordering AND whitespace. We
     * return the {@code X500Principal} itself, whose {@code toString} is SUN's
     * spaced form; BouncyCastle renders reversed and unspaced.
     * <p>
     * Fails if BouncyCastle adopts SUN's order, or if ours stops matching it.
     */
    @Test
    public void theDistinguishedNameRenderingDivergenceIsPinnedInBothHalves() throws Exception
    {
        int checked = 0;
        for (File f : corpus("certs").listFiles())
        {
            X509Certificate ours;
            X509Certificate theirs;
            try
            {
                ours = (X509Certificate) jsl.generateCertificate(new ByteArrayInputStream(read(f)));
                theirs = (X509Certificate) bc.generateCertificate(new ByteArrayInputStream(read(f)));
            }
            catch (Exception notACertificate)
            {
                continue;
            }
            // Ours answers from the same fact as getIssuerX500Principal.
            Assertions.assertEquals(ours.getIssuerX500Principal().toString(),
                    ours.getIssuerDN().toString(), f.getName() + ": our issuer rendering moved");
            // And BouncyCastle still renders it differently.
            Assertions.assertNotEquals(ours.getIssuerDN().toString(),
                    theirs.getIssuerDN().toString(),
                    f.getName() + ": BouncyCastle now renders the issuer as we do — this pin is stale");
            checked++;
        }
        Assertions.assertTrue(checked > 300, "only " + checked + " certificates were checked");
    }

    /**
     * {@code getSigAlgName} spelling. Ours is SUN's mixed case; BouncyCastle
     * upper-cases. Both halves pinned, and the COUNT of certificates where
     * they differ is asserted so a change in scope is visible.
     */
    @Test
    public void theSignatureAlgorithmNameDivergenceIsPinnedInBothHalves() throws Exception
    {
        int differ = 0;
        int same = 0;
        for (File f : corpus("certs").listFiles())
        {
            X509Certificate ours;
            X509Certificate theirs;
            try
            {
                ours = (X509Certificate) jsl.generateCertificate(new ByteArrayInputStream(read(f)));
                theirs = (X509Certificate) bc.generateCertificate(new ByteArrayInputStream(read(f)));
            }
            catch (Exception notACertificate)
            {
                continue;
            }
            // Whatever the spelling, the OID underneath must agree — that is
            // the fact; the name is a rendering of it.
            Assertions.assertEquals(theirs.getSigAlgOID(), ours.getSigAlgOID(), f.getName());
            if (ours.getSigAlgName().equals(theirs.getSigAlgName()))
            {
                same++;
            }
            else
            {
                differ++;
                Assertions.assertEquals(ours.getSigAlgName().toUpperCase(java.util.Locale.ROOT),
                        theirs.getSigAlgName().toUpperCase(java.util.Locale.ROOT),
                        f.getName() + ": the two spellings differ by more than case");
            }
        }
        Assertions.assertTrue(differ > 0,
                "BouncyCastle now spells every signature algorithm as we do — this pin is stale");
        Assertions.assertTrue(differ + same > 300, "the corpus is not being read");
    }

    /**
     * {@code getSigAlgParams}: an explicit ASN.1 NULL is "no parameters" to
     * SUN and to us, and the encoded NULL to BouncyCastle. Where the
     * parameters carry information both return the same bytes, so the
     * divergence is pinned only on the NULL case.
     */
    @Test
    public void theSignatureParametersDivergenceIsPinnedInBothHalves() throws Exception
    {
        int nullHere = 0;
        for (File f : corpus("certs").listFiles())
        {
            X509Certificate ours;
            X509Certificate theirs;
            try
            {
                ours = (X509Certificate) jsl.generateCertificate(new ByteArrayInputStream(read(f)));
                theirs = (X509Certificate) bc.generateCertificate(new ByteArrayInputStream(read(f)));
            }
            catch (Exception notACertificate)
            {
                continue;
            }
            byte[] mine = ours.getSigAlgParams();
            byte[] theirsParams = theirs.getSigAlgParams();
            if (mine == null)
            {
                nullHere++;
                // The explicit NULL BouncyCastle reports, when it reports one.
                if (theirsParams != null)
                {
                    Assertions.assertArrayEquals(new byte[]{0x05, 0x00}, theirsParams,
                            f.getName() + ": BouncyCastle reported parameters that are not an ASN.1 NULL");
                }
            }
            else
            {
                Assertions.assertArrayEquals(theirsParams, mine,
                        f.getName() + ": informative parameters must agree");
            }
        }
        Assertions.assertTrue(nullHere > 300,
                "only " + nullHere + " certificates reported absent parameters — this pin is stale "
                        + "if we have started emitting the explicit NULL");
    }

    /**
     * {@code getCertPathEncodings}: we serve PkiPath and PKCS7, BouncyCastle
     * also serves PEM. Divergence-report row 6, pinned both ways.
     */
    @Test
    public void theCertPathEncodingsDivergenceIsPinnedInBothHalves()
    {
        Set<String> ourEncodings = new TreeSet<String>();
        for (java.util.Iterator<String> it = jsl.getCertPathEncodings(); it.hasNext(); )
        {
            ourEncodings.add(it.next());
        }
        Set<String> theirEncodings = new TreeSet<String>();
        for (java.util.Iterator<String> it = bc.getCertPathEncodings(); it.hasNext(); )
        {
            theirEncodings.add(it.next());
        }

        Assertions.assertEquals(new TreeSet<String>(java.util.Arrays.asList("PKCS7", "PkiPath")),
                ourEncodings, "our certification-path encodings moved");
        Assertions.assertTrue(theirEncodings.contains("PEM"),
                "BouncyCastle no longer serves PEM — this pin is stale");
        Assertions.assertTrue(theirEncodings.containsAll(ourEncodings),
                "BouncyCastle no longer serves everything we do");
    }

    /**
     * A certification path we build is read back by BouncyCastle, and the
     * reverse, in both shared encodings — the interop a real peer performs.
     */
    @Test
    public void certificationPathsRoundTripThroughBouncyCastle() throws Exception
    {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (File f : corpus("certs").listFiles())
        {
            try
            {
                certs.add((X509Certificate) jsl.generateCertificate(new ByteArrayInputStream(read(f))));
            }
            catch (Exception notACertificate)
            {
                continue;
            }
            if (certs.size() == 3)
            {
                break;
            }
        }
        Assertions.assertEquals(3, certs.size(), "not enough certificates for a path");

        for (String encoding : new String[]{"PkiPath", "PKCS7"})
        {
            byte[] ourPath = jsl.generateCertPath(certs).getEncoded(encoding);
            Collection<? extends java.security.cert.Certificate> viaBc =
                    bc.generateCertPath(new ByteArrayInputStream(ourPath), encoding).getCertificates();
            Assertions.assertEquals(certs.size(), viaBc.size(),
                    encoding + ": BouncyCastle read back a different number of certificates");

            byte[] theirPath = bc.generateCertPath(certs).getEncoded(encoding);
            Assertions.assertArrayEquals(theirPath, ourPath,
                    encoding + ": the two encoders disagree on the path bytes");
        }
    }

    // -----------------------------------------------------------------
    // The BouncyCastle-minted corpus: the families PKITS cannot reach
    // -----------------------------------------------------------------

    /**
     * Every accessor on every certificate of every key family, ours against
     * BouncyCastle's, plus {@code getEncoded()} byte-equal to the DER that
     * went in.
     * <p>
     * PKITS is entirely RSA, so without this the elliptic-curve, Edwards and
     * post-quantum certificate paths through our parser are measured by
     * nothing. The equal-to-input assertion is separate from the
     * equal-to-BouncyCastle one: DER in must be DER out, and two parsers that
     * normalised the same way would satisfy the second while failing the
     * first.
     */
    @Test
    public void everyAccessorAgreesAcrossTheBouncyCastleMintedFamilies() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int certificates = 0;
        Set<String> families = new TreeSet<String>();

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            families.add(f.label);
            for (X509Certificate minted : f.allCertificates())
            {
                byte[] der = minted.getEncoded();
                X509Certificate ours = (X509Certificate) jsl.generateCertificate(
                        new ByteArrayInputStream(der));
                X509Certificate theirs = (X509Certificate) bc.generateCertificate(
                        new ByteArrayInputStream(der));
                certificates++;
                String n = f.label + "/" + ours.getSerialNumber();

                check(bad, n, "getEncoded is the input", Arrays.areEqual(der, ours.getEncoded()));
                check(bad, n, "getEncoded", Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()));
                check(bad, n, "getTBSCertificate",
                        Arrays.areEqual(ours.getTBSCertificate(), theirs.getTBSCertificate()));
                check(bad, n, "getSerialNumber",
                        ours.getSerialNumber().equals(theirs.getSerialNumber()));
                check(bad, n, "getVersion", ours.getVersion() == theirs.getVersion());
                check(bad, n, "getNotBefore", ours.getNotBefore().equals(theirs.getNotBefore()));
                check(bad, n, "getNotAfter", ours.getNotAfter().equals(theirs.getNotAfter()));
                check(bad, n, "getIssuerX500Principal",
                        ours.getIssuerX500Principal().equals(theirs.getIssuerX500Principal()));
                check(bad, n, "getSubjectX500Principal",
                        ours.getSubjectX500Principal().equals(theirs.getSubjectX500Principal()));
                check(bad, n, "getSigAlgOID", ours.getSigAlgOID().equals(theirs.getSigAlgOID()));
                check(bad, n, "getBasicConstraints",
                        ours.getBasicConstraints() == theirs.getBasicConstraints());
                check(bad, n, "getKeyUsage",
                        java.util.Arrays.equals(ours.getKeyUsage(), theirs.getKeyUsage()));
                check(bad, n, "getCriticalExtensionOIDs",
                        sorted(ours.getCriticalExtensionOIDs())
                                .equals(sorted(theirs.getCriticalExtensionOIDs())));
                check(bad, n, "getNonCriticalExtensionOIDs",
                        sorted(ours.getNonCriticalExtensionOIDs())
                                .equals(sorted(theirs.getNonCriticalExtensionOIDs())));
                check(bad, n, "hasUnsupportedCriticalExtension",
                        ours.hasUnsupportedCriticalExtension()
                                == theirs.hasUnsupportedCriticalExtension());
                check(bad, n, "getPublicKey.getEncoded",
                        Arrays.areEqual(ours.getPublicKey().getEncoded(),
                                theirs.getPublicKey().getEncoded()));

                for (String oid : sorted(ours.getCriticalExtensionOIDs()))
                {
                    check(bad, n, "getExtensionValue " + oid,
                            Arrays.areEqual(ours.getExtensionValue(oid),
                                    theirs.getExtensionValue(oid)));
                }
                for (String oid : sorted(ours.getNonCriticalExtensionOIDs()))
                {
                    check(bad, n, "getExtensionValue " + oid,
                            Arrays.areEqual(ours.getExtensionValue(oid),
                                    theirs.getExtensionValue(oid)));
                }
            }
        }

        Assertions.assertEquals(13, families.size(),
                "the corpus no longer carries thirteen key families: " + families);
        Assertions.assertEquals(65, certificates,
                "thirteen families of five certificates each were expected");
        Assertions.assertTrue(bad.isEmpty(),
                bad.size() + " accessor disagreements on the minted corpus:\n  "
                        + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 40))));
    }

    /**
     * {@code hasUnsupportedCriticalExtension}, pinned on all three providers
     * over three certificates that differ in one extension only.
     * <p>
     * The PKITS corpus cannot decide this. Across its 578 files exactly one
     * certificate and one CRL carry a critical extension outside the
     * supported set, and SUN and BouncyCastle agree on every file — so the
     * supported-extension list is indistinguishable from a different one
     * without certificates minted to separate them.
     * <p>
     * The one they separate is privateKeyUsagePeriod, and there we answer
     * with BouncyCastle rather than SUN: RFC 5280 dropped the extension, SUN
     * still parses it into a known type and so reports it understood, and we
     * do not honour it, so saying we do would be a claim we cannot keep. All
     * three answers are pinned, in every direction, so a move on any side
     * reports here rather than being absorbed.
     */
    @Test
    public void theUnsupportedCriticalExtensionAnswersArePinnedOnAllThree() throws Exception
    {
        CertificateFactory sun = CertificateFactory.getInstance("X.509");
        Assertions.assertEquals("SUN", sun.getProvider().getName(),
                "the JCA default X.509 factory is not SUN's, so this cell compares the wrong three");

        X509Certificate unknownCritical =
                endEntityOf("unknown-critical-extension");
        X509Certificate unknownNonCritical =
                endEntityOf("unknown-noncritical-extension");
        X509Certificate privateKeyUsagePeriod =
                endEntityOf("private-key-usage-period-critical");

        Assertions.assertAll(
                // An OID nobody can know: all three must say so.
                () -> Assertions.assertTrue(reparse(jsl, unknownCritical)
                        .hasUnsupportedCriticalExtension(), "ours on the unknown critical OID"),
                () -> Assertions.assertTrue(reparse(bc, unknownCritical)
                        .hasUnsupportedCriticalExtension(), "BouncyCastle on the unknown critical OID"),
                () -> Assertions.assertTrue(reparse(sun, unknownCritical)
                        .hasUnsupportedCriticalExtension(), "SUN on the unknown critical OID"),
                // The same OID non-critical: nothing to honour, so nobody objects.
                // Without this the cell would pass on an implementation that
                // answered true to everything.
                () -> Assertions.assertFalse(reparse(jsl, unknownNonCritical)
                        .hasUnsupportedCriticalExtension(), "ours on the unknown non-critical OID"),
                () -> Assertions.assertFalse(reparse(bc, unknownNonCritical)
                        .hasUnsupportedCriticalExtension(), "BouncyCastle on the unknown non-critical OID"),
                () -> Assertions.assertFalse(reparse(sun, unknownNonCritical)
                        .hasUnsupportedCriticalExtension(), "SUN on the unknown non-critical OID"),
                // privateKeyUsagePeriod: the one the three do not agree on.
                () -> Assertions.assertTrue(reparse(jsl, privateKeyUsagePeriod)
                                .hasUnsupportedCriticalExtension(),
                        "we now claim to understand a critical privateKeyUsagePeriod"),
                () -> Assertions.assertTrue(reparse(bc, privateKeyUsagePeriod)
                                .hasUnsupportedCriticalExtension(),
                        "BouncyCastle now understands a critical privateKeyUsagePeriod — "
                                + "this pin is stale"),
                () -> Assertions.assertFalse(reparse(sun, privateKeyUsagePeriod)
                                .hasUnsupportedCriticalExtension(),
                        "SUN no longer understands a critical privateKeyUsagePeriod — "
                                + "this pin is stale"));
    }

    private static X509Certificate endEntityOf(String shape) throws Exception
    {
        return BcBuiltChains.shape(shape).endEntity();
    }

    private static X509Certificate reparse(CertificateFactory f, X509Certificate c) throws Exception
    {
        return (X509Certificate) f.generateCertificate(new ByteArrayInputStream(c.getEncoded()));
    }

    // -----------------------------------------------------------------

    private static void check(List<String> bad, String file, String accessor, boolean ok)
    {
        if (!ok)
        {
            bad.add(file + " :: " + accessor);
        }
    }

    private static Set<String> sorted(Set<String> in)
    {
        return in == null ? new TreeSet<String>() : new TreeSet<String>(in);
    }

    private static Set<String> serials(X509CRL crl)
    {
        Set<String> out = new TreeSet<String>();
        Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
        if (entries != null)
        {
            for (X509CRLEntry e : entries)
            {
                out.add(e.getSerialNumber().toString(16));
            }
        }
        return out;
    }
}
