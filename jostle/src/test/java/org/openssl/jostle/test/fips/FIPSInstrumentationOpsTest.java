/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Infrastructure guard for FIPS operations-test instrumentation. Proves that a
 * JOSTLE_OPS_TEST build of the FIPS interface library wires up its own
 * {@link OperationsTestNI}: the flag-setting native symbol resolves and a
 * set/reset round-trip reaches {@code set_ops_test} inside the FIPS library and
 * returns. It does NOT assert any crypto fault-injection behaviour - the
 * per-family FIPS {@code *OpsTest} classes do that.
 *
 * <p>Gated twice: skipped when {@code TEST_FIPS_LIB} is unset (no FIPS module),
 * and skipped when the FIPS library carries no operations-test instrumentation
 * (a shipped, non-JOSTLE_OPS_TEST build - {@code opsTestAvailable()} is false).
 * A shipped FIPS library MUST NOT expose these symbols, so a skip there is the
 * correct, expected outcome.
 */
public class FIPSInstrumentationOpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final OperationsTestNI ops = FIPSNISelector.OperationsTestNI;

    @Test
    public void opsInstrumentationIsWired()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable(),
                "FIPS interface library built without JOSTLE_OPS (shipped build)");

        // Round-trip a flag through the FIPS library's own set_ops_test: this
        // exercises the Java -> FIPS-lib native binding end to end. resetFlags
        // clears every slot, so no state leaks to a later FIPS *OpsTest.
        ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
        ops.resetFlags();
    }
}
