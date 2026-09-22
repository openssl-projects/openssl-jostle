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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Known-answer coverage of the SecureRandom surface against the CAVP SP 800-90A
 * vectors, and byte agreement with BouncyCastle on the same rows.
 *
 * <p>A DRBG cannot be driven to a known answer without fixing its entropy, so
 * every cell here needs the operations-test hook: the class is excluded from the
 * unit legs by name and skips against a non-instrumented build. What the hook
 * supplies is the entropy and nothing else -- instantiate, reseed, generate and
 * dispose all run through the shipped {@code RandServiceNI} path, so a vector
 * exercises the code a caller reaches rather than a test-only generator.
 *
 * <p>The table is 156 blocks: the 13 section headers that map to a registered
 * name, x 4 (personalisation, additional input) configurations, x the three
 * sets. See {@code src/test/resources/drbg/README.md} for the selection rule and
 * why a subset is safe.
 */
public class RandAgreementOpsTest
{
    private final OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();
    private final RandServiceNI randServiceNI = TestNISelector.getRandNI();

    /**
     * Every registered SecureRandom name, mapped to the vector header it must be
     * covered by. DERIVED from {@link RandAlgorithm}'s own mechanism, variant and
     * derivation-function flag, so a registration that changes variant moves its
     * row instead of silently keeping the old one.
     *
     * <p>Five names share a header with another name: {@code DEFAULT} (the only
     * JCA alias, of {@code DRBG}), {@code DRBG} and {@code CTR-DRBG} resolve to
     * {@code AES-256 use df}, and the bare {@code HASH-DRBG} and {@code
     * HMAC-DRBG} to their {@code SHA-256} variants. They share the row rather
     * than duplicating its data.
     *
     * <p>Read by {@link RandAgreementTest} through the class literal; building it
     * touches no native code.
     */
    public static final Map<String, String> NAME_TO_HEADER;

    static
    {
        Map<String, String> names = new LinkedHashMap<String, String>();
        for (RandAlgorithm algorithm : RandAlgorithm.values())
        {
            names.put(algorithm.getJcaName(), headerFor(algorithm));
        }
        // The JCA alias carries no RandAlgorithm constant of its own.
        names.put("DEFAULT", headerFor(RandAlgorithm.DRBG));
        NAME_TO_HEADER = Collections.unmodifiableMap(names);
    }

    /** Maps a registration to the CAVP section header that covers it. */
    public static String headerFor(RandAlgorithm algorithm)
    {
        String mechanism = algorithm.getMechanism();
        String variant = algorithm.getVariant();
        if (mechanism.equals("CTR-DRBG"))
        {
            // The archive spells the derivation function into the header, and
            // every registered CTR name uses one.
            String cipher = variant.substring(0, variant.lastIndexOf("-CTR"));
            return "CTR_DRBG|" + cipher + (algorithm.usesDerivationFunction() ? " use df" : " no df");
        }
        String file = mechanism.equals("HASH-DRBG") ? "Hash_DRBG" : "HMAC_DRBG";
        String digest = variant.equals("SHA1") ? "SHA-1" : "SHA-" + variant.substring("SHA2-".length());
        return file + "|" + digest;
    }

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The answer is the SECOND generate, per the
     * archive's own Readme, and the first must differ from it. Asserting only
     * {@code gen2 == ReturnedBits} would pass against an implementation that
     * ignored the first generate entirely.
     */
    @Test
    public void everyCarriedVectorReproduces()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        List<String> failures = new ArrayList<String>();
        int driven = 0;
        for (CavpDrbgVectors.Vector v : CavpDrbgVectors.load())
        {
            driven++;
            try
            {
                byte[][] generated = CavpDrbgDriver.driveJostle(operationsTestNI, randServiceNI, v);
                if (!Arrays.areEqual(v.returnedBits, generated[1]))
                {
                    failures.add(v.key() + ": second generate does not match ReturnedBits");
                }
                if (Arrays.areEqual(v.returnedBits, generated[0]))
                {
                    failures.add(v.key() + ": FIRST generate matched ReturnedBits, so the"
                            + " second generate is not what is being measured");
                }
            }
            catch (RuntimeException e)
            {
                failures.add(v.key() + ": " + e.getMessage());
            }
        }

        Assertions.assertEquals(CavpDrbgVectors.EXPECTED_BLOCKS, driven,
                "drove " + driven + " vectors");
        Assertions.assertTrue(failures.isEmpty(),
                failures.size() + " of " + driven + " CAVP vectors failed:\n  "
                        + String.join("\n  ", failures.subList(0, Math.min(20, failures.size()))));
    }

    /**
     * Byte agreement with an INDEPENDENT implementation on the same
     * rows. Reproducing the published answer already proves correctness; this
     * additionally proves BC and OpenSSL consume the entropy in the same order,
     * which is the thing that differs between conforming implementations.
     *
     * <p>Driven through BC's lightweight {@code SP80090DRBG}, which takes
     * additional input on generate. The JCE-level builder cannot, so it appears
     * below as a per-mechanism witness instead.
     */
    @Test
    public void everyCarriedVectorAgreesWithBouncyCastle()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        List<String> failures = new ArrayList<String>();
        for (CavpDrbgVectors.Vector v : CavpDrbgVectors.load())
        {
            try
            {
                byte[][] ours = CavpDrbgDriver.driveJostle(operationsTestNI, randServiceNI, v);
                byte[][] theirs = CavpDrbgDriver.driveBouncyCastle(v);
                if (!Arrays.areEqual(ours[0], theirs[0]))
                {
                    failures.add(v.key() + ": first generate differs from BouncyCastle");
                }
                if (!Arrays.areEqual(ours[1], theirs[1]))
                {
                    failures.add(v.key() + ": second generate differs from BouncyCastle");
                }
                if (!Arrays.areEqual(v.returnedBits, theirs[1]))
                {
                    failures.add(v.key() + ": BouncyCastle does not reproduce ReturnedBits,"
                            + " so this row is not a comparison of two correct implementations");
                }
            }
            catch (RuntimeException e)
            {
                failures.add(v.key() + ": " + e.getMessage());
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                failures.size() + " rows disagreed with BouncyCastle:\n  "
                        + String.join("\n  ", failures.subList(0, Math.min(20, failures.size()))));
    }

    /**
     * The JCE-level API a caller actually reaches, on the rows it can express.
     * {@code SP800SecureRandom} exposes only {@code nextBytes(byte[])}, so rows
     * carrying additional input are out of its reach; those are covered above
     * through the lightweight API.
     */
    @Test
    public void theJceBuilderAgreesOnTheRowsItCanExpress()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        List<String> failures = new ArrayList<String>();
        Set<String> witnessed = new LinkedHashSet<String>();
        for (CavpDrbgVectors.Vector v : CavpDrbgVectors.load())
        {
            if (v.additionalInput1.length != 0 || v.additionalInput2.length != 0)
            {
                continue;
            }
            if (!witnessed.add(v.file + "|" + v.mechanism + "|" + v.set))
            {
                continue;
            }
            try
            {
                byte[][] builder = CavpDrbgDriver.driveBouncyCastleBuilder(v);
                byte[][] ours = CavpDrbgDriver.driveJostle(operationsTestNI, randServiceNI, v);
                if (!Arrays.areEqual(builder[1], v.returnedBits))
                {
                    failures.add(v.key() + ": builder does not reproduce ReturnedBits");
                }
                if (!Arrays.areEqual(builder[1], ours[1]))
                {
                    failures.add(v.key() + ": builder differs from Jostle");
                }
            }
            catch (RuntimeException e)
            {
                failures.add(v.key() + ": " + e.getMessage());
            }
        }

        // One witness per (header, set), asserted exactly, so the cell cannot pass
        // by witnessing nothing.
        Assertions.assertEquals(CavpDrbgVectors.mappedHeaders().size() * 3, witnessed.size(),
                "expected one builder witness per header per set, got " + witnessed);
        Assertions.assertTrue(failures.isEmpty(),
                "builder witnesses failed:\n  " + String.join("\n  ", failures));
    }

    /**
     * The selection is pinned as a SET of keys, not as a count: any 156 blocks
     * satisfy a count. No length is predicted -- the SHAPE is asserted, because
     * the non-zero personalisation and additional-input length does not track
     * the section's EntropyInputLen for every header.
     */
    @Test
    public void theSelectionIsExactlyWhatTheRuleProduces()
    {
        Assertions.assertEquals(CavpDrbgVectors.EXPECTED_BLOCKS, CavpDrbgVectors.keys().size(),
                "each block must carry a distinct selection key");

        Map<String, Set<String>> byHeader = CavpDrbgVectors.configsByHeader();
        Assertions.assertEquals(CavpDrbgVectors.mappedHeaders().size() * 3, byHeader.size(),
                "expected every mapped header in every one of the three sets");

        List<String> wrong = new ArrayList<String>();
        for (Map.Entry<String, Set<String>> entry : byHeader.entrySet())
        {
            Set<String> configs = entry.getValue();
            if (configs.size() != 4)
            {
                wrong.add(entry.getKey() + " has " + configs.size() + " configurations: " + configs);
                continue;
            }
            // Exactly one non-zero length N, present as (0,0) (0,N) (N,0) (N,N).
            Set<Integer> lengths = new TreeSet<Integer>();
            for (String config : configs)
            {
                String[] parts = config.split(",");
                lengths.add(Integer.parseInt(parts[0]));
                lengths.add(Integer.parseInt(parts[1]));
            }
            if (lengths.size() != 2 || !lengths.contains(0))
            {
                wrong.add(entry.getKey() + " lengths are " + lengths
                        + ", expected {0, N} for one N");
                continue;
            }
            int n = Collections.max(lengths);
            Set<String> expected = new LinkedHashSet<String>();
            expected.add("0,0");
            expected.add("0," + n);
            expected.add(n + ",0");
            expected.add(n + "," + n);
            if (!configs.equals(expected))
            {
                wrong.add(entry.getKey() + " has " + configs + ", expected " + expected);
            }
        }
        Assertions.assertTrue(wrong.isEmpty(), "malformed selection:\n  " + String.join("\n  ", wrong));

        Assertions.assertEquals(CavpDrbgVectors.mappedHeaders(), CavpDrbgVectors.headersPresent(),
                "the table carries a header that maps to no registered name, or is missing one");
    }

    /**
     * The headers the archive carries that NO registered name resolves to. Pinned
     * so that a header for a mechanism this provider DOES register, which fails
     * to parse or is dropped by the generator, is caught by name instead of
     * quietly joining the unregistered pile.
     */
    @Test
    public void theUnmappedHeadersAreExactlyTheUnregisteredSet()
    {
        Set<String> expected = new LinkedHashSet<String>();
        // No Triple-DES DRBG is registered.
        expected.add("CTR_DRBG|3KeyTDEA use df");
        expected.add("CTR_DRBG|3KeyTDEA no df");
        // Every registered CTR name carries useDerivationFunction = true.
        expected.add("CTR_DRBG|AES-128 no df");
        expected.add("CTR_DRBG|AES-192 no df");
        expected.add("CTR_DRBG|AES-256 no df");
        // The truncated SHA-512 variants are not registered.
        expected.add("Hash_DRBG|SHA-512/224");
        expected.add("Hash_DRBG|SHA-512/256");
        expected.add("HMAC_DRBG|SHA-512/224");
        expected.add("HMAC_DRBG|SHA-512/256");

        Set<String> unmapped = new LinkedHashSet<String>(CavpDrbgVectors.archiveHeaders());
        unmapped.removeAll(CavpDrbgVectors.mappedHeaders());

        Assertions.assertEquals(expected, unmapped);
        Assertions.assertEquals(CavpDrbgVectors.ARCHIVE_HEADERS,
                CavpDrbgVectors.mappedHeaders().size() + unmapped.size(),
                "mapped plus unmapped must account for every header in the archive");
    }

    /**
     * The derivation from {@link RandAlgorithm} must land on headers the table
     * actually carries. Without this the name-to-header map could resolve every
     * name to a row that does not exist, and the cross-reference guard in the
     * unit class would still pass.
     */
    @Test
    public void everyDerivedHeaderIsCarried()
    {
        Assertions.assertFalse(NAME_TO_HEADER.isEmpty(), "no registered names were derived");

        List<String> missing = new ArrayList<String>();
        for (Map.Entry<String, String> entry : NAME_TO_HEADER.entrySet())
        {
            if (!CavpDrbgVectors.mappedHeaders().contains(entry.getValue()))
            {
                missing.add(entry.getKey() + " -> " + entry.getValue());
            }
        }
        Assertions.assertTrue(missing.isEmpty(),
                "registered names resolve to headers the table does not carry:\n  "
                        + String.join("\n  ", missing));

        Set<String> covered = new LinkedHashSet<String>(NAME_TO_HEADER.values());
        Assertions.assertEquals(CavpDrbgVectors.mappedHeaders(), covered,
                "every carried header must be reachable from a registered name, and vice versa");
    }
}
