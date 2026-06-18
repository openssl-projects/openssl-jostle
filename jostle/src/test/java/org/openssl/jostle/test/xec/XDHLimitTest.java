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

package org.openssl.jostle.test.xec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * NI-layer input-validation tests for the XEC (X25519 / X448) key-generation
 * bridge. Calls {@link XECServiceNI} directly so the C bridge layer's
 * null / type checks surface as the same JCE-friendly exceptions and typed
 * error codes exercised by the higher-level SPI tests.
 *
 * <p>Key agreement (the kex path) is shared with EC and is covered by
 * {@code ECLimitTest}; XEC adds only key generation, so this file covers the
 * {@code ni_generateKeyPair} surface only.
 */
public class XDHLimitTest
{
    private final XECServiceNI xec = TestNISelector.getXECNi();


    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // generateKeyPair — bridge null / type validation
    // -----------------------------------------------------------------

    @Test
    public void XECServiceNI_generateKeyPair_nullName()
    {
        try
        {
            xec.generateKeyPair(null, TestUtil.RNDSrc);
            Assertions.fail("expected NullPointerException");
        }
        catch (NullPointerException expected)
        {
            Assertions.assertEquals("name is null", expected.getMessage());
        }
    }

    @Test
    public void XECServiceNI_ni_generateKeyPair_nullName_returnsTypedCode()
    {
        // Direct NI call surfaces the typed error code in err[0] so callers
        // bypassing the throwing wrapper can distinguish the cause.
        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair(null, err, TestUtil.RNDSrc);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL.getCode(), err[0]);
    }

    @Test
    public void XECServiceNI_generateKeyPair_nullRand()
    {
        try
        {
            xec.generateKeyPair("X25519", null);
            Assertions.fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException expected)
        {
            // JO_RAND_NO_RAND_UP_CALL → "supplied random source was null"
            Assertions.assertEquals("supplied random source was null", expected.getMessage());
        }
    }

    @Test
    public void XECServiceNI_ni_generateKeyPair_nullRand_returnsTypedCode()
    {
        int[] err = new int[1];
        long ref = xec.ni_generateKeyPair("X25519", err, null);
        Assertions.assertEquals(0L, ref);
        Assertions.assertEquals(ErrorCode.JO_RAND_NO_RAND_UP_CALL.getCode(), err[0]);
    }

    /**
     * An unrecognised key-type name reaches {@code EVP_PKEY_CTX_new_from_name},
     * which returns NULL → {@code JO_OPENSSL_ERROR}. The SPI only ever passes
     * "X25519" / "X448", so this is reachable only at the NI surface. The real
     * OpenSSL queue content varies, so the message is prefix-matched per the
     * Limit-test message-pinning convention.
     */
    @Test
    public void XECServiceNI_generateKeyPair_unknownName_throwsOpenSSLError()
    {
        try
        {
            xec.generateKeyPair("definitely-not-a-real-key-type", TestUtil.RNDSrc);
            Assertions.fail("expected OpenSSLException for an unknown key type");
        }
        catch (OpenSSLException expected)
        {
            Assertions.assertTrue(expected.getMessage().startsWith("OpenSSL Error:"),
                    "unexpected message: " + expected.getMessage());
        }
    }
}
