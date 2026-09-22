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

package org.openssl.jostle.test.rand;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.util.Arrays;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SecureRandom coverage that needs no fixed entropy, so it runs on every unit
 * leg rather than only an operations-test build.
 *
 * <p>The known-answer work lives in {@link RandAgreementOpsTest}, which a plain
 * build cannot run. This class carries the half that does not need the hook, and
 * the cross-reference guard that ties the two together: every registered name
 * must be covered by a row in that class's table. Reading the table touches no
 * native code, so the guard is meaningful here.
 */
public class RandAgreementTest
{
    private static final int SAMPLE = 64;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static Provider provider()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /**
     * Every registered SecureRandom name, primaries and aliases alike. Aliases
     * are read from the {@code Alg.Alias.SecureRandom.*} properties, because
     * {@code getServices()} reports primaries only.
     */
    public static Set<String> registeredNames(Provider provider)
    {
        Set<String> names = new LinkedHashSet<String>();
        for (Provider.Service service : provider.getServices())
        {
            if (service.getType().equals("SecureRandom"))
            {
                names.add(service.getAlgorithm());
            }
        }
        String prefix = "Alg.Alias.SecureRandom.";
        for (String key : provider.stringPropertyNames())
        {
            if (key.startsWith(prefix))
            {
                names.add(key.substring(prefix.length()));
            }
        }
        return names;
    }

    /**
     * The loader must accept either line-ending form. This cell derives both
     * from one checkout, so no platform is the only witness.
     */
    @Test
    public void theTableIsIndependentOfTheCheckoutsLineEndings()
    {
        byte[] lf = CavpDrbgVectors.normalise(CavpDrbgVectors.resourceBytes());
        byte[] crlf = new String(lf, StandardCharsets.US_ASCII).replace("\n", "\r\n")
                .getBytes(StandardCharsets.US_ASCII);

        // True of any file carrying a newline, so it holds whatever git did.
        Assertions.assertNotEquals(CavpDrbgVectors.sha256Hex(lf), CavpDrbgVectors.sha256Hex(crlf),
                "the two forms are identical, so this cell would compare the file with itself");

        String manifest = CavpDrbgVectors.manifestSha256();
        Assertions.assertEquals(manifest, CavpDrbgVectors.sha256Hex(CavpDrbgVectors.normalise(lf)),
                "the LF form does not match the manifest");
        Assertions.assertEquals(manifest, CavpDrbgVectors.sha256Hex(CavpDrbgVectors.normalise(crlf)),
                "the manifest check is not independent of line endings");

        List<CavpDrbgVectors.Vector> fromLf = CavpDrbgVectors.parse(lf);
        List<CavpDrbgVectors.Vector> fromCrlf = CavpDrbgVectors.parse(crlf);
        List<CavpDrbgVectors.Vector> loaded = CavpDrbgVectors.load();

        Assertions.assertEquals(CavpDrbgVectors.EXPECTED_BLOCKS, fromCrlf.size());
        Assertions.assertEquals(fromLf.size(), fromCrlf.size());
        Assertions.assertEquals(loaded.size(), fromCrlf.size());

        List<String> lfKeys = new ArrayList<String>();
        List<String> crlfKeys = new ArrayList<String>();
        List<String> loadedKeys = new ArrayList<String>();
        for (int i = 0; i < fromCrlf.size(); i++)
        {
            lfKeys.add(fromLf.get(i).key());
            crlfKeys.add(fromCrlf.get(i).key());
            loadedKeys.add(loaded.get(i).key());
            Assertions.assertTrue(Arrays.areEqual(fromLf.get(i).returnedBits,
                            fromCrlf.get(i).returnedBits),
                    "ReturnedBits differ at " + fromCrlf.get(i).key());
            Assertions.assertTrue(Arrays.areEqual(loaded.get(i).returnedBits,
                            fromCrlf.get(i).returnedBits),
                    "ReturnedBits differ from the loaded table at " + fromCrlf.get(i).key());
        }
        Assertions.assertEquals(lfKeys, crlfKeys);
        Assertions.assertEquals(loadedKeys, crlfKeys);
    }

    /**
     * The cross-reference guard. A name registered with no vector row is a name
     * whose output nothing has ever compared against a published answer, and
     * nothing else in the suite would notice.
     */
    @Test
    public void everyRegisteredNameHasAVectorRow()
    {
        Set<String> names = registeredNames(provider());

        // Vacuity: an empty surface satisfies every "for each name" loop below.
        Assertions.assertTrue(names.size() >= RandAlgorithm.values().length,
                "only " + names.size() + " SecureRandom names found, expected at least the "
                        + RandAlgorithm.values().length + " RandAlgorithm constants");

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
            // 4 (ps, ai) configurations x 3 sets.
            if (rows != 12)
            {
                uncovered.add(name + " -> " + header + " has " + rows + " rows, expected 12");
            }
        }
        Assertions.assertTrue(uncovered.isEmpty(),
                "registered SecureRandom names without vector coverage:\n  "
                        + String.join("\n  ", uncovered));

        // And the reverse: a table entry naming something unregistered is a stale
        // row that would otherwise sit there testing nothing.
        List<String> stale = new ArrayList<String>();
        for (String name : table.keySet())
        {
            if (!names.contains(name))
            {
                stale.add(name);
            }
        }
        Assertions.assertTrue(stale.isEmpty(), "vector table names unregistered algorithms: " + stale);
    }

    /**
     * The strength each registration reports, against the CAVP section that
     * covers it. The vectors are an INDEPENDENT source -- NIST's, not OpenSSL's --
     * so this cannot pass by comparing one transcription with another. The
     * archive's EntropyInputLen is the section's security strength throughout.
     */
    @Test
    public void strengthMatchesTheCavpSectionForEveryRegistration()
    {
        List<String> wrong = new ArrayList<String>();
        int checked = 0;
        for (RandAlgorithm algorithm : RandAlgorithm.values())
        {
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
            int actual = algorithm.getMaxStrength();
            if (actual != expected)
            {
                wrong.add(algorithm.getJcaName() + " reports strength " + actual
                        + ", the CAVP " + header + " section is " + expected);
            }
        }
        Assertions.assertEquals(RandAlgorithm.values().length, checked,
                "every registration must have been checked");
        Assertions.assertTrue(wrong.isEmpty(), String.join("\n  ", wrong));
    }

    /**
     * What the configurable default actually resolves to.
     *
     * <p>Prediction resistance is NOT part of the registration: neither
     * {@code RandAlgorithm} nor {@code DrbgConfig} carries such a field, so
     * there is nothing here to assert it on. It is a CALLER capability, read
     * from {@code DrbgParameters.Instantiation.getCapability()} and defaulting
     * to {@code RESEED_ONLY}, in the {@code java9} override of
     * {@code RandServiceSPI} -- the copy that runs on every leg above 8. The
     * Java 8 baseline passes {@code false} because Java 8 has no
     * {@code DrbgParameters} to read, which is a limitation of that source
     * level rather than the contract.
     *
     * <p>The capability itself is pinned in {@code src/test/java25}, where the
     * JDK 9+ API is available:
     * {@code RandServiceParameterTest.nextBytesRejectsPredictionResistanceWithoutCapability}
     * and {@code nextBytesPredictionResistanceIsSupportedWithCapability}, with
     * the FIPS twin in {@code FIPSRandParameterTest}. The vectors exercise the
     * resistant path independently, driving the NI directly.
     */
    @Test
    public void drbgAndDefaultResolveToCtrAes256WithTheDerivationFunction()
    {
        RandAlgorithm drbg = RandAlgorithm.DRBG;
        Assertions.assertEquals("CTR-DRBG", drbg.getMechanism());
        Assertions.assertEquals("AES-256-CTR", drbg.getVariant());
        Assertions.assertTrue(drbg.usesDerivationFunction(), "the default must use the derivation function");
        Assertions.assertEquals("CTR_DRBG|AES-256 use df", RandAgreementOpsTest.headerFor(drbg));

        // DEFAULT is an alias of DRBG, so both must reach the same implementation.
        Provider.Service viaDefault = provider().getService("SecureRandom", "DEFAULT");
        Provider.Service viaDrbg = provider().getService("SecureRandom", "DRBG");
        Assertions.assertNotNull(viaDefault, "DEFAULT is not registered");
        Assertions.assertNotNull(viaDrbg, "DRBG is not registered");
        Assertions.assertEquals(viaDrbg.getClassName(), viaDefault.getClassName(),
                "DEFAULT must resolve to the same SPI as DRBG");
    }

    /** A stub returning a constant, or one instance's state leaking to another, fails here. */
    @Test
    public void twoInstancesOfEveryRegisteredNameDiffer() throws Exception
    {
        List<String> same = new ArrayList<String>();
        for (String name : registeredNames(provider()))
        {
            byte[] a = new byte[SAMPLE];
            byte[] b = new byte[SAMPLE];
            SecureRandom.getInstance(name, JostleProvider.PROVIDER_NAME).nextBytes(a);
            SecureRandom.getInstance(name, JostleProvider.PROVIDER_NAME).nextBytes(b);
            if (Arrays.areEqual(a, b))
            {
                same.add(name);
            }
        }
        Assertions.assertTrue(same.isEmpty(), "two fresh instances produced identical output: " + same);
    }

    /**
     * {@code setSeed} is ADDITIVE: it reseeds with the caller's bytes mixed into
     * the existing state, it does not replace that state. So seeding two
     * instances identically must NOT make them agree.
     *
     * <p>The JDK contract permits either reading, and the difference matters: a
     * caller who believes seeding is deterministic will build a reproducible
     * stream that is not reproducible. A test that only seeded one instance and
     * asserted it still produced bytes would pass under either behaviour.
     */
    @Test
    public void setSeedIsAdditiveRatherThanReplacing() throws Exception
    {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);

        List<String> deterministic = new ArrayList<String>();
        for (String name : registeredNames(provider()))
        {
            SecureRandom first = SecureRandom.getInstance(name, JostleProvider.PROVIDER_NAME);
            SecureRandom second = SecureRandom.getInstance(name, JostleProvider.PROVIDER_NAME);
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
                "the same seed produced the same stream, so setSeed replaced the state"
                        + " rather than adding to it: " + deterministic);
    }
}
