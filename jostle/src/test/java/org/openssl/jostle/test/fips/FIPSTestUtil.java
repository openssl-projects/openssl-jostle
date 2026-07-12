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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;

import java.io.File;

/**
 * Shared bootstrap for the env-gated FIPS tests. The single switch is the
 * {@code TEST_FIPS_LIB} environment variable (a full path to the FIPS module
 * library); everything here derives from it via {@link TestUtil}. All tests
 * construct the provider from the SAME resolved configuration, so the
 * one-shot native initialisation dedups across test classes sharing a JVM.
 */
final class FIPSTestUtil
{
    private FIPSTestUtil()
    {
    }

    /**
     * A genuine, non-named 2048-bit PKCS#3 safe prime (generator g = 2),
     * produced once with {@code openssl dhparam 2048} and pinned here.
     * Tests that prove the FIPS q-less DH rejection MUST use a prime that
     * is NOT an RFC 7919 / RFC 3526 named group: OpenSSL recognises a
     * named-group (p, g) pair on import and silently back-fills the
     * subgroup order q, which would disarm the very SP 800-56A q-check
     * those tests exist to exercise (the first review probe was
     * contaminated exactly this way by harvesting ffdhe2048 components).
     */
    static final String NON_NAMED_SAFE_PRIME_2048_HEX =
            "FCFEF6884ADDB08BF50CF530266529EEA5C111C1CDF35436AD82FB2198EAE6C5"
                    + "3409790433D42D3EC4CD6AAA2CD1F0191801A0C0FD8B6B6BE275A5BB3301B2EF"
                    + "1C894E68BB7A930C681D8B38C2ABB34FAF01A41E5E50EFC7813789A9C14DF9B1"
                    + "3132BE4EB73C2A5824C0944F2826E3392C756D88D29BC4547FB9684C65FA4536"
                    + "537489C5BB80DCF3DA5616557B14CBDE366CD9D709631F37AAE45C60045CF157"
                    + "F571B498D979235CE136C6A6A281B4A8688F056EEE918C0178DAB8CAF9431355"
                    + "B796F17C96DADCE788C2EAA3373D86B4F016CE8CF26B369EAC5D6B990277029F"
                    + "8697B35F83C972FDDE048EB404AF37A2FE308BA91218B84EAF2DF42C3D5E12FF";

    /**
     * Skip the calling test unless a FIPS module is configured
     * ({@code TEST_FIPS_LIB}); otherwise ensure the JSLFIPS provider is
     * registered and return it.
     */
    static JostleFIPSProvider assumeFipsProvider()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        return TestUtil.addFipsProvider();
    }

    /**
     * The FIPS module library file named by {@code TEST_FIPS_LIB}. Only call
     * after {@link #assumeFipsProvider()} (or an equivalent skip guard) has
     * established the variable is set.
     */
    static File fipsModuleFile()
    {
        return new File(TestUtil.fipsLibPath());
    }

    /**
     * The directory containing the FIPS module (and, by convention, its
     * {@code fipsmodule.cnf}).
     */
    static String fipsModuleDir()
    {
        return fipsModuleFile().getParent();
    }
}
