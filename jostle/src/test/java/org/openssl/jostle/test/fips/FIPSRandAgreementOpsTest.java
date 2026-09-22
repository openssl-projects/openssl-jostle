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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.rand.CavpDrbgDriver;
import org.openssl.jostle.test.rand.CavpDrbgVectors;
import org.openssl.jostle.test.rand.RandAgreementOpsTest;
import org.openssl.jostle.test.rand.RandAgreementTest;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The JSLFIPS half of {@link RandAgreementOpsTest}: the CAVP vectors driven
 * through the FIPS interface library and the module's own lib ctx, plus the
 * guard that the fixed-entropy hook does not leave approved mode relaxed.
 *
 * <p>Only the headers JSLFIPS registers are driven: it does not register the
 * SHA-224 and SHA-384 Hash and HMAC variants, so those rows have no
 * registration here to be a vector for.
 *
 * <p>Requires a {@code JOSTLE_OPS_TEST} build of the FIPS library: the class
 * skips whole when {@code TEST_FIPS_LIB} is unset, and per test on
 * {@code opsTestAvailable()} against a shipped, non-instrumented library.
 */
public class FIPSRandAgreementOpsTest
{
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;
    private final RandServiceNI randServiceNI = FIPSNISelector.RandServiceNI;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    /** The vector rows whose header a JSLFIPS registration resolves to. */
    private static List<CavpDrbgVectors.Vector> fipsRows()
    {
        Set<String> headers = new LinkedHashSet<String>();
        for (String name : RandAgreementTest.registeredNames(
                Security.getProvider(JostleFIPSProvider.PROVIDER_NAME)))
        {
            String header = RandAgreementOpsTest.NAME_TO_HEADER.get(name);
            if (header != null)
            {
                headers.add(header);
            }
        }

        List<CavpDrbgVectors.Vector> rows = new ArrayList<CavpDrbgVectors.Vector>();
        for (CavpDrbgVectors.Vector v : CavpDrbgVectors.load())
        {
            if (headers.contains(v.file + "|" + v.mechanism))
            {
                rows.add(v);
            }
        }
        return rows;
    }

    /**
     * The same contract as the base class, through the module: the answer is the
     * SECOND generate and the first must differ from it.
     */
    @Test
    public void everyCarriedVectorTheModuleServesReproduces()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        List<CavpDrbgVectors.Vector> rows = fipsRows();

        // 9 registered headers x 4 configurations x 3 sets. A filter that matched
        // nothing would make every loop below vacuous.
        Assertions.assertEquals(9 * 4 * 3, rows.size(),
                "expected the nine FIPS-registered headers in all four configurations"
                        + " and all three sets, got " + rows.size() + " rows");

        List<String> failures = new ArrayList<String>();
        for (CavpDrbgVectors.Vector v : rows)
        {
            try
            {
                byte[][] generated = CavpDrbgDriver.driveJostle(operationsTestNI, randServiceNI, v);
                if (!Arrays.areEqual(v.returnedBits, generated[1]))
                {
                    failures.add(v.key() + ": second generate does not match ReturnedBits");
                }
                if (Arrays.areEqual(v.returnedBits, generated[0]))
                {
                    failures.add(v.key() + ": FIRST generate matched ReturnedBits");
                }
            }
            catch (RuntimeException e)
            {
                failures.add(v.key() + ": " + e.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                failures.size() + " of " + rows.size() + " vectors failed:\n  "
                        + String.join("\n  ", failures.subList(0, Math.min(20, failures.size()))));
    }

    /** Byte agreement with BouncyCastle on the rows the module serves. */
    @Test
    public void everyCarriedVectorTheModuleServesAgreesWithBouncyCastle()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        List<String> failures = new ArrayList<String>();
        List<CavpDrbgVectors.Vector> rows = fipsRows();
        for (CavpDrbgVectors.Vector v : rows)
        {
            try
            {
                byte[][] ours = CavpDrbgDriver.driveJostle(operationsTestNI, randServiceNI, v);
                byte[][] theirs = CavpDrbgDriver.driveBouncyCastle(v);
                if (!Arrays.areEqual(ours[1], theirs[1]))
                {
                    failures.add(v.key() + ": second generate differs from BouncyCastle");
                }
                if (!Arrays.areEqual(v.returnedBits, theirs[1]))
                {
                    failures.add(v.key() + ": BouncyCastle does not reproduce ReturnedBits");
                }
            }
            catch (RuntimeException e)
            {
                failures.add(v.key() + ": " + e.getMessage());
            }
        }
        Assertions.assertTrue(failures.isEmpty(),
                failures.size() + " of " + rows.size() + " rows disagreed with BouncyCastle:\n  "
                        + String.join("\n  ", failures.subList(0, Math.min(20, failures.size()))));
    }

    /**
     * The hook must not leave approved mode relaxed.
     *
     * <p>The FIPS lib ctx pins {@code fips=yes} as its default property query,
     * and that pin is the approved-mode gate for the whole context. The
     * fixed-entropy hook reaches TEST-RAND, which ships INSIDE the validated
     * module flagged unapproved, by fetching with {@code "-fips"} for that one
     * object -- OpenSSL's own {@code test/evp_test.c} :2450-2451 says TEST-RAND
     * "is available in the FIPS provider but not with fips=yes". A fetch that
     * relaxed the CONTEXT instead of the one object would leave every later
     * operation resolving outside the module, producing correct-looking output
     * that nothing behavioural could distinguish.
     *
     * <p>{@code op_randLibctxFipsEnabled} answers about the context the
     * SecureRandom service actually fetches through, so this asserts the
     * property rather than inferring it from a provider name. It discriminates:
     * measured false on the base tree and true on the FIPS tree, on both
     * bridges.
     */
    @Test
    public void theFixedEntropyHookLeavesApprovedModeIntact()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        // The probe aborts before the provider has initialised its rand ctx, so
        // registration in @BeforeAll is a precondition, not tidiness.
        Assertions.assertTrue(operationsTestNI.op_randLibctxFipsEnabled(),
                "the FIPS rand lib ctx does not pin approved mode before any hook use");

        CavpDrbgVectors.Vector row = fipsRows().get(0);
        byte[][] generated = CavpDrbgDriver.driveJostle(operationsTestNI, randServiceNI, row);
        Assertions.assertTrue(Arrays.areEqual(row.returnedBits, generated[1]),
                "the hook did not drive " + row.key() + ", so this cell proves nothing");

        Assertions.assertTrue(operationsTestNI.op_randLibctxFipsEnabled(),
                "driving a fixed-entropy DRBG relaxed approved mode on the rand lib ctx");

        // And the production path still reaches the module's approved CTR-DRBG.
        int[] err = new int[1];
        long ref = randServiceNI.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 256,
                false, null, err);
        Assertions.assertNotEquals(0, ref,
                "a production DRBG could not be created after the hook ran: err=" + err[0]);
        try
        {
            byte[] first = new byte[64];
            byte[] second = new byte[64];
            Assertions.assertTrue(randServiceNI.ni_contextRandomBytes(ref, first, first.length,
                    256, false, null) >= 0, "production generate failed");
            Assertions.assertTrue(randServiceNI.ni_contextRandomBytes(ref, second, second.length,
                    256, false, null) >= 0, "production generate failed");
            Assertions.assertFalse(Arrays.areEqual(first, second),
                    "the production DRBG repeated itself after the hook ran");
        }
        finally
        {
            randServiceNI.ni_disposeContext(ref);
        }

        Assertions.assertEquals("fips",
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_RAND, "CTR-DRBG"),
                "CTR-DRBG is no longer served by the module after the hook ran");
    }

    /**
     * The control for the cell above. A probe that can only answer the wanted
     * value is not a probe: under {@code fips=yes} the module must NOT resolve
     * TEST-RAND, which is the whole reason the hook has to ask for it with
     * {@code "-fips"}. If this ever returns {@code "fips"}, the approved-mode
     * pin is not doing anything and the assertions above would pass regardless.
     */
    @Test
    public void testRandIsNotResolvableUnderApprovedMode()
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        String provider = FIPSNISelector.OpenSSLFIPSNI
                .implementingProvider(OpenSSLFIPSNI.OP_RAND, "TEST-RAND");
        Assertions.assertNotEquals("fips", provider,
                "TEST-RAND resolved under fips=yes, so the approved-mode pin discriminates"
                        + " nothing and the no-mutation cell is vacuous");
    }
}
