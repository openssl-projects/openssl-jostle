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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

/**
 * Input-validation limit tests at the FIPS XEC (X25519 / X448) key-generation
 * NI surface ({@link FIPSNISelector#XECServiceNI}). The FIPS JNI glue is the
 * base xec_ni_jni.c re-included under renamed symbols, so the bridge's null /
 * type checks and typed-error mapping are identical by construction — this pins
 * that they survived into the FIPS interface library with the same messages.
 * Mirrors the base {@code XDHLimitTest}.
 *
 * <p>FIPS note: X25519/X448 are deliberately NOT registered by the JSLFIPS
 * provider (cert #4985 does not approve them), but the xec bridge is still
 * compiled into the FIPS interface library, so its input validation is still
 * a live contract worth pinning. Every test here rejects at the bridge (null
 * name / null rand) or at {@code EVP_PKEY_CTX_new_from_name} (unknown name) —
 * none exercises a real X25519 keygen, so the coverage does not depend on the
 * module approving the algorithm.
 *
 * <p>Key agreement (the kex path) is shared with EC and covered by
 * {@code FIPSECLimitTest}; XEC adds only key generation, so this file covers
 * the {@code ni_generateKeyPair} surface only.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 */
public class FIPSXDHLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final XECServiceNI xec = FIPSNISelector.XECServiceNI;

    // -----------------------------------------------------------------
    // generateKeyPair — bridge null / type validation
    // -----------------------------------------------------------------

    @Test
    public void generateKeyPair_nullName()
    {
        assertNPE("name is null", () -> xec.generateKeyPair(null, RND));
    }

    @Test
    public void ni_generateKeyPair_nullName_returnsTypedCode()
    {
        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair(null, err, RND);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(), err[0]);
    }

    @Test
    public void generateKeyPair_nullRand()
    {
        assertIAE("supplied random source was null", () -> xec.generateKeyPair("X25519", null));
    }

    @Test
    public void ni_generateKeyPair_nullRand_returnsTypedCode()
    {
        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair("X25519", err, null);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(ErrorCode.JO_RAND_NO_RAND_UP_CALL.getCode(), err[0]);
    }

    /**
     * An unrecognised key-type name reaches {@code EVP_PKEY_CTX_new_from_name},
     * which returns NULL → {@code JO_OPENSSL_ERROR}. Reachable only at the NI
     * surface. The real OpenSSL queue content varies, so the message is
     * prefix-matched per the Limit-test message-pinning convention.
     */
    @Test
    public void generateKeyPair_unknownName_throwsOpenSSLError()
    {
        OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                () -> xec.generateKeyPair("definitely-not-a-real-key-type", RND));
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + e.getMessage());
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static void assertIAE(String message, Executable action)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }

    private static void assertNPE(String message, Executable action)
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }
}
