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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Group C item 1: every registered {@code AlgorithmParameters} name must be
 * USABLE, not merely registered.
 *
 * <h2>The gap this closes</h2>
 *
 * <p>Four names — the AES-128 and AES-192 GCM/CCM OIDs
 * {@code 2.16.840.1.101.3.4.1.6}, {@code .7}, {@code .26}, {@code .27} —
 * appeared in the test tree exactly twice each, both times inside a
 * golden-surface list in {@code ServedSurfaceSnapshotTest} /
 * {@code FIPSServedSurfaceSnapshotTest}, and were never passed to
 * {@code getInstance}. Their AES-256 twins ({@code .46}, {@code .47}) were
 * driven through named constants in {@code AESParametersTest}. So the snapshot
 * pinned that the names were REGISTERED while nothing checked they WORKED —
 * the registration-is-not-usability shape that let five families break while
 * the FIPS snapshot stayed green.
 *
 * <p>It was found by asking what POSITIVE coverage existed, not by adding
 * fault cells: a negative-path survey over those names would have produced
 * four tidy divergence rows and never noticed the names are unexercised.
 *
 * <h2>Why it reads the LIVE provider</h2>
 *
 * <p>A hard-coded list of twenty names cannot catch the twenty-first. The
 * names come from {@code provider.getServices()}, and a name whose SPI class
 * has no spec maker below FAILS the test rather than being skipped — so the
 * next never-constructed name cannot hide the way these four did.
 *
 * <p>Twenty names are only SEVEN SPI classes, so there are seven makers, not
 * twenty. Measured: CBC 3 names, CCM 4, GCM 4, Iv 6, DH 1, DSA 1, EC 1.
 */
public class AlgorithmParametersNameCompleteSmokeTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Reused across names: DH/DSA parameter generation is slow. */
    private static AlgorithmParameterSpec dhSpec;
    private static AlgorithmParameterSpec dsaSpec;

    @BeforeAll
    public static void setUp() throws Exception
    {
        jsl = new JostleProvider();
        Security.addProvider(jsl);
        bc = new BouncyCastleProvider();
        Security.addProvider(bc);

        AlgorithmParameterGenerator dh = AlgorithmParameterGenerator.getInstance("DH", jsl);
        dh.init(1024);
        dhSpec = dh.generateParameters().getParameterSpec(DHParameterSpec.class);

        AlgorithmParameterGenerator dsa = AlgorithmParameterGenerator.getInstance("DSA", jsl);
        dsa.init(1024);
        dsaSpec = dsa.generateParameters().getParameterSpec(DSAParameterSpec.class);
    }

    /**
     * The spec to init a name with, chosen by its SPI class rather than its
     * name — seven makers for twenty names. Returns null when the class is
     * unknown, which the caller turns into a FAILURE.
     */
    private static AlgorithmParameterSpec specFor(String spiClass)
    {
        byte[] iv16 = new byte[16];
        byte[] iv12 = new byte[12];
        RANDOM.nextBytes(iv16);
        RANDOM.nextBytes(iv12);

        if (spiClass.endsWith("CBCAlgorithmParameters") || spiClass.endsWith("IvAlgorithmParameters"))
        {
            return new IvParameterSpec(iv16);
        }
        if (spiClass.endsWith("GCMAlgorithmParameters") || spiClass.endsWith("CCMAlgorithmParameters"))
        {
            // Tag length stated explicitly: CCM's BC-parity default is 64 and
            // GCM's is 128, so an IvParameterSpec here would compare two
            // different tag lengths across providers.
            return new GCMParameterSpec(128, iv12);
        }
        if (spiClass.endsWith("DHAlgorithmParameters"))
        {
            return dhSpec;
        }
        if (spiClass.endsWith("DSAAlgorithmParameters"))
        {
            return dsaSpec;
        }
        if (spiClass.endsWith("ECAlgorithmParameters"))
        {
            return new ECGenParameterSpec("secp256r1");
        }
        return null;
    }

    /**
     * Every string {@code AlgorithmParameters.getInstance} accepts, mapped to
     * the SPI class that serves it — primaries AND aliases.
     *
     * <p>Aliases are included because "name-complete" has to mean what a
     * caller can ask for. Measured on JSL: 20 primaries and 18 aliases, 38 in
     * all. The aliases are not a rounding error — they include every
     * {@code OID.}-prefixed form of the nine AES OIDs, the bare DSA/EC/DH
     * OIDs, {@code DIFFIEHELLMAN}, and the ChaCha20-Poly1305 OID.
     *
     * <p>They must be read from the {@code Alg.Alias.} property entries:
     * {@code Provider.Service} exposes {@code getAlgorithm()} and has NO
     * public {@code getAliases()}, so a services-only scan cannot see them.
     */
    private static TreeMap<String, String> resolvableNames(Provider p)
    {
        TreeMap<String, String> byName = new TreeMap<String, String>();
        for (Provider.Service s : p.getServices())
        {
            if ("AlgorithmParameters".equals(s.getType()))
            {
                byName.put(s.getAlgorithm(), s.getClassName());
            }
        }
        final String prefix = "Alg.Alias.AlgorithmParameters.";
        for (Object k : p.keySet())
        {
            String key = (String) k;
            if (!key.startsWith(prefix))
            {
                continue;
            }
            String alias = key.substring(prefix.length());
            String target = p.getProperty(key);
            String cls = byName.get(target);
            Assertions.assertNotNull(cls,
                    "alias " + alias + " points at " + target + ", which is not a primary");
            byName.put(alias, cls);
        }
        return byName;
    }

    /**
     * Every registered name: getInstance, init(spec), getEncoded, then a
     * SECOND instance init(encoded) and re-encode equal. Both directions of
     * the encoder are exercised, which a one-way init would not do.
     */
    @Test
    public void everyRegisteredNameInitsEncodesAndDecodes() throws Exception
    {
        TreeMap<String, String> names = resolvableNames(jsl);
        Assertions.assertFalse(names.isEmpty(), "vacuity: no AlgorithmParameters registered");

        List<String> failures = new ArrayList<String>();
        int exercised = 0;

        for (java.util.Map.Entry<String, String> e : names.entrySet())
        {
            String name = e.getKey();
            AlgorithmParameterSpec spec = specFor(e.getValue());
            if (spec == null)
            {
                // NOT a skip. An unknown SPI class means a name nobody has
                // written a maker for, which is exactly how the four AES
                // OIDs stayed unexercised.
                failures.add(name + ": no spec maker for SPI class " + e.getValue()
                        + " — add one rather than skipping");
                continue;
            }
            try
            {
                AlgorithmParameters ap = AlgorithmParameters.getInstance(name, jsl);
                ap.init(spec);
                byte[] enc = ap.getEncoded();
                Assertions.assertNotNull(enc, name + ": getEncoded returned null");
                Assertions.assertTrue(enc.length > 0, name + ": getEncoded returned empty");

                AlgorithmParameters back = AlgorithmParameters.getInstance(name, jsl);
                back.init(enc);
                Assertions.assertTrue(Arrays.areEqual(enc, back.getEncoded()),
                        name + ": re-encode after decode differs");
                exercised++;
            }
            catch (Throwable t)
            {
                failures.add(name + " (" + e.getValue() + "): " + t);
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                "AlgorithmParameters names that are registered but not usable:\n  "
                        + String.join("\n  ", failures));
        Assertions.assertEquals(names.size(), exercised,
                "every registered name must have been exercised");
    }

    /**
     * The BC leg, and the reason it matters here: the four AES-128/192 GCM/CCM
     * OIDs had no witness but themselves. An encoding both providers accept is
     * an independent check that the bytes mean what we think.
     *
     * <h2>What each of the three assertions actually proves</h2>
     *
     * <p>The two round-trips prove ACCEPTANCE — each provider takes the
     * other's bytes and re-emits them unchanged. They are coverage, not the
     * witness of encoder agreement, because a decoder that RETAINED its input
     * would satisfy them while agreeing about nothing. The third assertion,
     * comparing the two FROM-SPEC encodings, is the witness.
     *
     * <p>Measured for this surface: neither provider retains input. Feeding
     * both a valid but NON-CANONICAL encoding — RFC 5084 gives the GCM tag
     * length a DEFAULT of 12 bytes, so stating it explicitly is well-formed
     * and canonically wrong — has each of them re-derive and emit the same
     * shorter canonical form. So the round-trips here are genuine. That is a
     * fact about this surface, not a general one: a key type whose decoder
     * caches the original encoding makes the same shape vacuous, and the test
     * for it is a non-canonical form rather than a round-trip.
     */
    @Test
    public void everyNameBcAlsoRegistersRoundTripsBothDirections() throws Exception
    {
        TreeMap<String, String> names = resolvableNames(jsl);
        List<String> failures = new ArrayList<String>();
        TreeSet<String> compared = new TreeSet<String>();

        for (java.util.Map.Entry<String, String> e : names.entrySet())
        {
            String name = e.getKey();
            AlgorithmParameterSpec spec = specFor(e.getValue());
            if (spec == null)
            {
                continue;   // reported by the test above; not double-counted here
            }
            AlgorithmParameters bcAp;
            try
            {
                bcAp = AlgorithmParameters.getInstance(name, bc);
            }
            catch (Exception notInBc)
            {
                continue;   // legitimately absent from BC
            }
            try
            {
                // jostle -> BC
                AlgorithmParameters ours = AlgorithmParameters.getInstance(name, jsl);
                ours.init(spec);
                byte[] ourEnc = ours.getEncoded();
                bcAp.init(ourEnc);
                Assertions.assertTrue(Arrays.areEqual(ourEnc, bcAp.getEncoded()),
                        name + ": BC re-encoded our bytes differently");

                // BC -> jostle
                AlgorithmParameters bcFresh = AlgorithmParameters.getInstance(name, bc);
                bcFresh.init(spec);
                byte[] bcEnc = bcFresh.getEncoded();
                AlgorithmParameters oursBack = AlgorithmParameters.getInstance(name, jsl);
                oursBack.init(bcEnc);
                Assertions.assertTrue(Arrays.areEqual(bcEnc, oursBack.getEncoded()),
                        name + ": we re-encoded BC's bytes differently");

                // The two FROM-SPEC encodings must agree with each other. The
                // two round-trips above do NOT imply this: two encoders that
                // differ — say one writing a default tag length explicitly and
                // the other omitting it — would each accept the other's bytes
                // and pass both directions while never producing the same
                // output. This is the assertion that catches that.
                Assertions.assertTrue(Arrays.areEqual(ourEnc, bcEnc),
                        name + ": jostle and BC encode the SAME spec differently"
                                + " — pin the divergence by name with a reason"
                                + " rather than loosening this");

                compared.add(name);
            }
            catch (Throwable t)
            {
                failures.add(name + ": " + t);
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                "BC round-trip failures:\n  " + String.join("\n  ", failures));
        // Vacuity floor. Measured: 38 names resolve on JSL and BC registers 25
        // of them, so 20 leaves headroom for BC to drop a few without making
        // this brittle, while still failing if the comparison collapses. The
        // floor was 15 when the sweep was primaries-only; aliases raised the
        // population, so the floor moved with it rather than staying
        // proportionally looser.
        Assertions.assertTrue(compared.size() >= 20,
                "expected BC to share at least 20 names, compared only " + compared.size()
                        + ": " + compared);
    }

    /**
     * The four names this item exists for, pinned BY NAME as well as by the
     * sweep. If someone narrows the sweep, these still have to work.
     */
    @Test
    public void theFourPreviouslyUnexercisedAesOidsWork() throws Exception
    {
        String[] oids = {
                "2.16.840.1.101.3.4.1.6",    // AES-128 GCM
                "2.16.840.1.101.3.4.1.7",    // AES-128 CCM
                "2.16.840.1.101.3.4.1.26",   // AES-192 GCM
                "2.16.840.1.101.3.4.1.27",   // AES-192 CCM
        };
        byte[] iv12 = new byte[12];
        RANDOM.nextBytes(iv12);
        for (String oid : oids)
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance(oid, jsl);
            ap.init(new GCMParameterSpec(128, iv12));
            byte[] enc = ap.getEncoded();
            AlgorithmParameters back = AlgorithmParameters.getInstance(oid, jsl);
            back.init(enc);
            Assertions.assertTrue(Arrays.areEqual(enc, back.getEncoded()),
                    oid + ": round-trip differs");
        }
    }
}
