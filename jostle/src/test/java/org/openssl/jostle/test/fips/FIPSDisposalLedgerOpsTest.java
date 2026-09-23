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
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.disposal.DisposalLedgerOpsTest;
import org.openssl.jostle.util.ops.OperationsTestNI;
import org.openssl.jostle.util.ops.OperationsTestNI.LedgerType;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The JSLFIPS half of the native ledger, read from the FIPS interface library.
 *
 * <p>Also the cross-library check: while JSLFIPS creates and drops its handles,
 * the BASE library's ledger must not move, except for the key pair the DSA
 * driver borrows from JSL where the module refuses to generate one (two key
 * specs and their two encodings), and those must balance. A FIPS handle freed
 * through the base library would show there as a destroy with no create.
 */
public class FIPSDisposalLedgerOpsTest extends DisposalLedgerOpsTest
{
    private Map<LedgerType, int[]> baseBefore;

    @BeforeAll
    public static void requireFipsModule()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Override
    protected Provider provider()
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
    }

    @Override
    protected OperationsTestNI ops()
    {
        return FIPSNISelector.OperationsTestNI;
    }

    /** Measured: 15 types on the 3.1.2 module, 17 on 3.5.8. */
    @Override
    protected int minimumTypesExpected()
    {
        return 15;
    }

    @Override
    protected void beforeDriving()
    {
        OperationsTestNI base = NISelector.OperationsTestNI;
        Assumptions.assumeTrue(base.opsTestAvailable(), "the base library is not an operations-test build");
        baseBefore = snapshot(base);
    }

    /**
     * When no driver imported, nothing crossed and the base ledger must be
     * untouched for every type. When one did, exactly KEY_SPEC and ASN1_CTX
     * may move in the base library (the borrowed pair and its two encodings),
     * both balanced, and every other type stays untouched.
     */
    @Override
    protected void afterDraining(List<String> modes)
    {
        boolean imported = false;
        for (String m : modes)
        {
            imported |= m.contains("imported");
        }
        Map<LedgerType, int[]> after = snapshot(NISelector.OperationsTestNI);
        List<String> unbalanced = new ArrayList<String>();
        List<String> moved = new ArrayList<String>();
        for (LedgerType t : LedgerType.values())
        {
            int dc = after.get(t)[0] - baseBefore.get(t)[0];
            int dd = after.get(t)[1] - baseBefore.get(t)[1];
            if (dc != dd)
            {
                unbalanced.add(t + " created+" + dc + " destroyed+" + dd);
            }
            boolean allowed = imported && (t == LedgerType.KEY_SPEC || t == LedgerType.ASN1_CTX);
            if ((dc != 0 || dd != 0) && !allowed)
            {
                moved.add(t + " created+" + dc + " destroyed+" + dd);
            }
        }
        System.out.println("[ledger-base-delta] imported=" + imported + " unbalanced=" + unbalanced
                + " moved=" + moved);
        Assertions.assertTrue(unbalanced.isEmpty(),
                "the base library's ledger went unbalanced during a JSLFIPS drain: " + unbalanced);
        Assertions.assertTrue(moved.isEmpty(),
                "the base library's ledger moved during a JSLFIPS drain where nothing crossed: " + moved);
    }
}
