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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.rand.CavpDrbgVectors;
import org.openssl.jostle.test.rand.RandAgreementOpsTest;
import org.openssl.jostle.test.rand.RandAgreementTest;
import org.openssl.jostle.util.Arrays;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The JSLFIPS half of {@link RandAgreementTest}: SecureRandom coverage that
 * needs no fixed entropy, over the names the FIPS provider registers.
 *
 * <p>Neither class substitutes for the other. They drive different native
 * libraries through different lib ctxs, and each guards its OWN provider's
 * registered set -- a JSL-only registration is invisible here, and a JSLFIPS-only
 * one is invisible there.
 *
 * <p>JSLFIPS registers a strict subset: it does not register the SHA-224 and
 * SHA-384 Hash and HMAC variants. That is a property of the registration code,
 * not of the loaded module, so it is asserted identically on both modules.
 */
public class FIPSRandAgreementTest
{
    private static final int SAMPLE = 64;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private static Provider provider()
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
    }

    /**
     * Every name JSLFIPS registers must be covered by a vector row. The table is
     * shared with the base class because the CAVP sections are the same; what
     * differs is which of them this provider reaches.
     */
    @Test
    public void everyRegisteredNameHasAVectorRow()
    {
        Set<String> names = RandAgreementTest.registeredNames(provider());

        Assertions.assertFalse(names.isEmpty(), "JSLFIPS registers no SecureRandom names");

        Map<String, String> table = RandAgreementOpsTest.NAME_TO_HEADER;
        List<String> uncovered = new ArrayList<String>();
        for (String name : names)
        {
            String header = table.get(name);
            if (header == null)
            {
                uncovered.add(name + " has no entry in the vector table");
                continue;
            }
            int rows = 0;
            for (CavpDrbgVectors.Vector v : CavpDrbgVectors.load())
            {
                if ((v.file + "|" + v.mechanism).equals(header))
                {
                    rows++;
                }
            }
            if (rows != 12)
            {
                uncovered.add(name + " -> " + header + " has " + rows + " rows, expected 12");
            }
        }
        Assertions.assertTrue(uncovered.isEmpty(),
                "JSLFIPS names without vector coverage:\n  " + String.join("\n  ", uncovered));
    }

    /**
     * The registered set is a strict subset of the base provider's, and exactly
     * which names are missing is the assertion -- a count would be satisfied by
     * dropping any four.
     */
    @Test
    public void theTruncatedSha2DrbgVariantsAreNotRegistered()
    {
        Set<String> names = RandAgreementTest.registeredNames(provider());

        Set<String> mustBeAbsent = new LinkedHashSet<String>();
        mustBeAbsent.add("HASH-DRBG-SHA224");
        mustBeAbsent.add("HASH-DRBG-SHA384");
        mustBeAbsent.add("HMAC-DRBG-SHA224");
        mustBeAbsent.add("HMAC-DRBG-SHA384");

        List<String> present = new ArrayList<String>();
        for (String name : mustBeAbsent)
        {
            if (names.contains(name))
            {
                present.add(name);
            }
        }
        Assertions.assertTrue(present.isEmpty(),
                "JSLFIPS must not register the SHA-224 and SHA-384 Hash and HMAC"
                        + " variants, but it registers: " + present);

        // The other side of the same fact: everything else IS registered, so a
        // change that dropped the whole family would not pass as compliance.
        List<String> missing = new ArrayList<String>();
        for (RandAlgorithm algorithm : RandAlgorithm.values())
        {
            if (!mustBeAbsent.contains(algorithm.getJcaName())
                    && !names.contains(algorithm.getJcaName()))
            {
                missing.add(algorithm.getJcaName());
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "JSLFIPS is missing approved registrations: " + missing);

        Assertions.assertEquals(RandAlgorithm.values().length - mustBeAbsent.size() + 1,
                names.size(),
                "expected every approved constant plus the DEFAULT alias, got " + names);
    }

    /**
     * Strength per registration against the CAVP section, read through the FIPS
     * NI so the module answers rather than mainline.
     */
    @Test
    public void strengthMatchesTheCavpSectionForEveryRegistration()
    {
        Set<String> names = RandAgreementTest.registeredNames(provider());

        List<String> wrong = new ArrayList<String>();
        int checked = 0;
        for (RandAlgorithm algorithm : RandAlgorithm.values())
        {
            if (!names.contains(algorithm.getJcaName()))
            {
                continue;
            }
            String header = RandAgreementOpsTest.headerFor(algorithm);
            int expected = -1;
            for (CavpDrbgVectors.Vector v : CavpDrbgVectors.load())
            {
                if ((v.file + "|" + v.mechanism).equals(header))
                {
                    expected = v.entropyInputLen;
                    break;
                }
            }
            if (expected < 0)
            {
                wrong.add(algorithm.getJcaName() + " -> " + header + ": no vector row");
                continue;
            }
            checked++;
            int actual = algorithm.getMaxStrength(FIPSNISelector.RandServiceNI);
            if (actual != expected)
            {
                wrong.add(algorithm.getJcaName() + " reports strength " + actual
                        + ", the CAVP " + header + " section is " + expected);
            }
        }
        Assertions.assertTrue(checked > 0, "no FIPS registration was checked");
        Assertions.assertTrue(wrong.isEmpty(), String.join("\n  ", wrong));
    }

    @Test
    public void twoInstancesOfEveryRegisteredNameDiffer() throws Exception
    {
        List<String> same = new ArrayList<String>();
        for (String name : RandAgreementTest.registeredNames(provider()))
        {
            byte[] a = new byte[SAMPLE];
            byte[] b = new byte[SAMPLE];
            SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME).nextBytes(a);
            SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME).nextBytes(b);
            if (Arrays.areEqual(a, b))
            {
                same.add(name);
            }
        }
        Assertions.assertTrue(same.isEmpty(), "two fresh instances produced identical output: " + same);
    }

    /** Seeding is additive here too; see the base class for why the distinction matters. */
    @Test
    public void setSeedIsAdditiveRatherThanReplacing() throws Exception
    {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);

        List<String> deterministic = new ArrayList<String>();
        for (String name : RandAgreementTest.registeredNames(provider()))
        {
            SecureRandom first = SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            SecureRandom second = SecureRandom.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            first.setSeed(seed);
            second.setSeed(seed);

            byte[] a = new byte[SAMPLE];
            byte[] b = new byte[SAMPLE];
            first.nextBytes(a);
            second.nextBytes(b);
            if (Arrays.areEqual(a, b))
            {
                deterministic.add(name);
            }
        }
        Assertions.assertTrue(deterministic.isEmpty(),
                "the same seed produced the same stream: " + deterministic);
    }
}
