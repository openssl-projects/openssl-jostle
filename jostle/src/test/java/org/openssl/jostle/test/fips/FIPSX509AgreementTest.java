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

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.certpath.BcBuiltChains;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Every X.509 accessor on the JSLFIPS factory, against BouncyCastle, over the
 * {@link BcBuiltChains} corpus.
 *
 * <p><b>Why this is not covered by its JSL twin.</b> The two providers drive
 * different native libraries ({@code libinterface_fips_*} against
 * {@code libinterface_*}) through different {@code OSSL_LIB_CTX}s, so a
 * defect in one is invisible to the other; and the JSL twin reads
 * {@code JostleProvider.getServices()}, which cannot see a JSLFIPS
 * registration at all. Neither substitutes for the other.
 *
 * <p><b>Why the BouncyCastle corpus and not PKITS.</b> PKITS is entirely RSA.
 * The question this class exists to answer — does the FIPS factory parse and
 * key every family the loaded module serves — has no PKITS material for the
 * elliptic-curve, Edwards or post-quantum families, which is most of what a
 * FIPS module change moves. {@code FIPSX509CertificateFactoryTest} already
 * covers the provider-bound policy on a hand-built certificate; this covers
 * the breadth.
 *
 * <p><b>A family the module does not serve is skipped BY NAME, and the module
 * is asked rather than the provider.</b> Asking the provider would compare
 * the registration with itself: a registrar that dropped a family the module
 * serves would then read as a module that does not serve it. The count of
 * families actually measured is asserted, so a probe name that matches
 * nothing empties the sweep loudly instead of turning it green.
 */
public class FIPSX509AgreementTest
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static JostleFIPSProvider fips;
    private static CertificateFactory jslFips;
    private static CertificateFactory bc;

    @BeforeAll
    static void before() throws Exception
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        jslFips = CertificateFactory.getInstance("X.509", fips);
        bc = CertificateFactory.getInstance("X.509", BC);
        Assertions.assertEquals(BC, bc.getProvider().getName(),
                "the reference factory did not come from BouncyCastle");
        Assertions.assertSame(fips, jslFips.getProvider(),
                "the factory under test is not the FIPS provider instance");
    }

    /** Does the loaded module implement this family's key type? */
    private static boolean served(BcBuiltChains.Family f)
    {
        return FIPSTestUtil.moduleServesKeyMgmt(f.keyManagementName);
    }

    // -----------------------------------------------------------------

    /**
     * Every accessor on every certificate of every served family, ours
     * against BouncyCastle's. Failures are collected and reported together,
     * so one divergent family does not hide the rest.
     */
    @Test
    public void everyCertificateAccessorAgreesWithBouncyCastle() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        Set<String> measured = new TreeSet<String>();
        Set<String> skipped = new TreeSet<String>();
        int certificates = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            if (!served(f))
            {
                skipped.add(f.label);
                continue;
            }
            measured.add(f.label);
            for (X509Certificate minted : f.allCertificates())
            {
                byte[] der = minted.getEncoded();
                X509Certificate ours = (X509Certificate) jslFips.generateCertificate(
                        new ByteArrayInputStream(der));
                X509Certificate theirs = (X509Certificate) bc.generateCertificate(
                        new ByteArrayInputStream(der));
                certificates++;
                String n = f.label + "/" + shortSubject(minted);

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

        System.out.println("FIPSX509AgreementTest: measured " + measured
                + ", not served by this module " + skipped);
        Assertions.assertTrue(measured.size() >= 6,
                "only " + measured.size() + " families were measured " + measured
                        + " — either the module serves almost nothing, or a probe name "
                        + "matches nothing and the sweep is empty");
        Assertions.assertEquals(measured.size() * 5, certificates,
                "each measured family carries five certificates");
        Assertions.assertTrue(bad.isEmpty(),
                bad.size() + " accessor disagreements with BouncyCastle:\n  "
                        + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 40))));
    }

    /**
     * Every CRL accessor, with the revoked entries compared as SETS — the JCA
     * returns a Set, so an ordering difference is not a divergence and must
     * not read as one.
     */
    @Test
    public void everyCrlAccessorAgreesWithBouncyCastle() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int compared = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            if (!served(f))
            {
                continue;
            }
            for (X509CRL minted : f.crls())
            {
                byte[] der = minted.getEncoded();
                X509CRL ours = (X509CRL) jslFips.generateCRL(new ByteArrayInputStream(der));
                X509CRL theirs = (X509CRL) bc.generateCRL(new ByteArrayInputStream(der));
                compared++;
                String n = f.label + "/" + ours.getIssuerX500Principal().getName();

                check(bad, n, "getEncoded is the input", Arrays.areEqual(der, ours.getEncoded()));
                check(bad, n, "getEncoded", Arrays.areEqual(ours.getEncoded(), theirs.getEncoded()));
                check(bad, n, "getTBSCertList",
                        Arrays.areEqual(ours.getTBSCertList(), theirs.getTBSCertList()));
                check(bad, n, "getIssuerX500Principal",
                        ours.getIssuerX500Principal().equals(theirs.getIssuerX500Principal()));
                check(bad, n, "getThisUpdate", ours.getThisUpdate().equals(theirs.getThisUpdate()));
                check(bad, n, "getNextUpdate", ours.getNextUpdate().equals(theirs.getNextUpdate()));
                check(bad, n, "getSigAlgOID", ours.getSigAlgOID().equals(theirs.getSigAlgOID()));
                check(bad, n, "revoked serials as a SET", serials(ours).equals(serials(theirs)));
            }
        }

        Assertions.assertTrue(compared >= 12,
                "only " + compared + " CRLs were compared — the sweep is empty");
        Assertions.assertTrue(bad.isEmpty(),
                bad.size() + " CRL accessor disagreements with BouncyCastle:\n  "
                        + String.join("\n  ", bad.subList(0, Math.min(bad.size(), 40))));
    }

    /**
     * A key taken out of a certificate by the FIPS factory belongs to the
     * FIPS provider INSTANCE.
     * <p>
     * Compared by identity, not by name: a name is re-resolvable, and a
     * {@code CertificateFactory} obtained through {@code getInstance(alg,
     * Provider)} need never have been registered under one. Comparing the
     * key's encoding instead would pass whoever built it, which is precisely
     * the fact under test.
     */
    @Test
    public void everyKeyTakenFromACertificateBelongsToTheFipsProviderInstance() throws Exception
    {
        int checked = 0;
        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            if (!served(f))
            {
                continue;
            }
            PublicKey key = ((X509Certificate) jslFips.generateCertificate(
                    new ByteArrayInputStream(f.ee.getEncoded()))).getPublicKey();
            Assertions.assertTrue(key instanceof OSSLKey,
                    f.label + ": the FIPS factory returned a key that is not one of ours: "
                            + key.getClass().getName());
            Provider owner = ((OSSLKey) key).getSpec().getProviderInstance();
            Assertions.assertSame(fips, owner,
                    f.label + ": the key was created by " + (owner == null ? "no provider" : owner.getName())
                            + " rather than by the FIPS provider instance");
            checked++;
        }
        Assertions.assertTrue(checked >= 6,
                "only " + checked + " families were checked — the sweep is empty");
    }

    /**
     * A certification path the FIPS factory encodes is read back by
     * BouncyCastle, and the reverse, byte-equal in both shared encodings.
     */
    @Test
    public void everyServedFamilysPathRoundTripsThroughBouncyCastle() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int round = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            if (!served(f))
            {
                continue;
            }
            List<X509Certificate> certs = f.chain();
            for (String encoding : new String[]{"PkiPath", "PKCS7"})
            {
                byte[] ours = jslFips.generateCertPath(certs).getEncoded(encoding);
                byte[] theirs = bc.generateCertPath(certs).getEncoded(encoding);
                if (!Arrays.areEqual(ours, theirs))
                {
                    bad.add(f.label + " :: " + encoding + " :: the two encoders disagree");
                    continue;
                }
                List<? extends Certificate> back = bc.generateCertPath(
                        new ByteArrayInputStream(ours), encoding).getCertificates();
                if (back.size() != certs.size())
                {
                    bad.add(f.label + " :: " + encoding + " :: BouncyCastle read back "
                            + back.size() + " of " + certs.size());
                }
                round++;
            }
        }

        Assertions.assertTrue(round >= 12,
                "only " + round + " round trips ran — the sweep is empty");
        Assertions.assertTrue(bad.isEmpty(),
                bad.size() + " path encoding disagreements:\n  " + String.join("\n  ", bad));
    }

    /**
     * The gate is real in both directions: what the module says it serves,
     * the factory keys; what it says it does not, the factory refuses loudly
     * rather than quietly handing back a key from somewhere else.
     * <p>
     * Without the second half the skips above would be unfalsifiable — a
     * probe answering "no" to everything would empty the sweep and leave
     * every remaining cell green.
     */
    @Test
    public void theModuleGateAgreesWithWhatTheFactoryCanKey() throws Exception
    {
        List<String> bad = new ArrayList<String>();
        int served = 0;
        int refused = 0;

        for (BcBuiltChains.Family f : BcBuiltChains.families())
        {
            boolean moduleServes = served(f);
            boolean keyed;
            try
            {
                ((X509Certificate) jslFips.generateCertificate(
                        new ByteArrayInputStream(f.ee.getEncoded()))).getPublicKey();
                keyed = true;
            }
            catch (ProviderException refusal)
            {
                // Only the refusal this factory raises for a key type the
                // module does not serve counts as "not served". A catch wide
                // enough to hold a NullPointerException would read a genuine
                // bug on an unserved family as agreement with the module,
                // which is the one answer this cell must never give.
                String said = String.valueOf(refusal.getMessage());
                Assertions.assertTrue(said.contains("serves no KeyFactory"),
                        f.label + ": the FIPS factory refused with a ProviderException that is "
                                + "not the unserved-key-type refusal: " + said);
                Assertions.assertTrue(said.contains(f.publicKeyAlgorithmOid),
                        f.label + ": the refusal does not name the certificate's public key "
                                + "algorithm " + f.publicKeyAlgorithmOid + ": " + said);
                keyed = false;
            }
            if (moduleServes != keyed)
            {
                bad.add(f.label + " :: the module says " + (moduleServes ? "served" : "not served")
                        + " and the factory " + (keyed ? "keyed it" : "refused it"));
            }
            if (moduleServes)
            {
                served++;
            }
            else
            {
                refused++;
            }
        }

        Assertions.assertTrue(bad.isEmpty(), String.join("\n  ", bad));
        Assertions.assertTrue(served > 0,
                "the module serves no family in the corpus; the probe is answering no to everything");
        System.out.println("FIPSX509AgreementTest: module serves " + served
                + " families and not " + refused + " (" + FIPSTestUtil.moduleDescription() + ")");
    }

    // -----------------------------------------------------------------

    private static void check(List<String> bad, String where, String accessor, boolean ok)
    {
        if (!ok)
        {
            bad.add(where + " :: " + accessor);
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

    private static String shortSubject(X509Certificate c)
    {
        String dn = c.getSubjectX500Principal().getName();
        int comma = dn.indexOf(',');
        return comma < 0 ? dn : dn.substring(0, comma);
    }
}
