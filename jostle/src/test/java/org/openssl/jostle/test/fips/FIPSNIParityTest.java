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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;

import java.security.SecureRandom;
import java.security.Security;

/**
 * Bridge-contract parity between the base and FIPS interface libraries at
 * the raw NI surface: identical invalid inputs must produce identical typed
 * error codes from both. The FIPS JNI glue is the base bridge re-included
 * under renamed symbols, so this holds by construction today - the test
 * pins the contract against future drift (e.g. a fips glue file gaining
 * logic beyond renames, or the two libraries compiling different bridge
 * revisions). Every probe below is a bridge-validated failure that touches
 * no native state, so the test is order-independent and repeatable.
 *
 * <p>Gated on JOSTLE_TEST_FIPS_DIR; skipped when unset.
 */
public class FIPSNIParityTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void mdBridgeCodesMatch()
    {
        ensureProviders();

        // Null digest name is rejected at the bridge.
        int[] baseErr = new int[1];
        int[] fipsErr = new int[1];
        NISelector.MDServiceNI.ni_allocateDigest(null, 0, baseErr);
        FIPSNISelector.MDServiceNI.ni_allocateDigest(null, 0, fipsErr);
        Assertions.assertEquals(baseErr[0], fipsErr[0], "null-name codes must match");
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL, ErrorCode.forCode(fipsErr[0]));

        // Unknown digest name fails the fetch in both lib ctxs with the same code.
        NISelector.MDServiceNI.ni_allocateDigest("NoSuchDigest-XYZ", 0, baseErr);
        FIPSNISelector.MDServiceNI.ni_allocateDigest("NoSuchDigest-XYZ", 0, fipsErr);
        Assertions.assertEquals(baseErr[0], fipsErr[0], "unknown-name codes must match");
    }

    @Test
    public void macBridgeCodesMatch()
    {
        ensureProviders();

        int[] baseErr = new int[1];
        int[] fipsErr = new int[1];
        NISelector.MacServiceNI.ni_allocateMac(null, "SHA2-256", baseErr);
        FIPSNISelector.MacServiceNI.ni_allocateMac(null, "SHA2-256", fipsErr);
        Assertions.assertEquals(baseErr[0], fipsErr[0], "null-mac-name codes must match");
        Assertions.assertEquals(ErrorCode.JO_NAME_IS_NULL, ErrorCode.forCode(fipsErr[0]));
    }

    @Test
    public void kdfBridgeCodesMatch()
    {
        ensureProviders();

        // Null password, then negative iteration count - both bridge-validated.
        int base = NISelector.KdfNI.pbkdf2(null, new byte[8], 100, "SHA-256", new byte[16], 0, 16);
        int fips = FIPSNISelector.KdfNI.pbkdf2(null, new byte[8], 100, "SHA-256", new byte[16], 0, 16);
        Assertions.assertEquals(base, fips, "null-password codes must match");

        base = NISelector.KdfNI.pbkdf2(new byte[8], new byte[8], -1, "SHA-256", new byte[16], 0, 16);
        fips = FIPSNISelector.KdfNI.pbkdf2(new byte[8], new byte[8], -1, "SHA-256", new byte[16], 0, 16);
        Assertions.assertEquals(base, fips, "negative-iter codes must match");
    }

    @Test
    public void randBridgeCodesMatch()
    {
        ensureProviders();

        // Unknown DRBG mechanism fails the fetch in both rand lib ctxs.
        int base = NISelector.RandServiceNI.ni_drbgStrength("NOT-A-MECHANISM", "SHA2-256");
        int fips = FIPSNISelector.RandServiceNI.ni_drbgStrength("NOT-A-MECHANISM", "SHA2-256");
        Assertions.assertEquals(base, fips, "unknown-mechanism codes must match");
        Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR, ErrorCode.forCode(fips));
    }

    @Test
    public void asn1BridgeCodesMatch()
    {
        ensureProviders();

        // Structurally invalid DER fails the decode in both lib ctxs; the
        // failure is rolled back (no PKEY allocated).
        byte[] garbage = new byte[64];
        RANDOM.nextBytes(garbage);
        garbage[0] = (byte) 0xFF; // never a valid DER SEQUENCE header

        long base = NISelector.Asn1NI.ni_fromPublicKeyInfo(garbage, 0, garbage.length);
        long fips = FIPSNISelector.Asn1NI.ni_fromPublicKeyInfo(garbage, 0, garbage.length);
        Assertions.assertEquals(base, fips, "invalid-DER codes must match");
        Assertions.assertTrue(fips < 0, "invalid DER must be rejected");
    }
}
