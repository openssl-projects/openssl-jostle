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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.test.TestUtil;

import javax.crypto.SecretKeyFactory;
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * The memory-hard password KDFs — scrypt (RFC 7914) and Argon2 (RFC 9106) — are
 * excluded from the FIPS provider <b>structurally</b>, and this pins that at
 * every layer the exclusion exists at.
 *
 * <p>Neither is served by the OpenSSL FIPS provider: in OpenSSL 3.6.2 both build
 * only into {@code libdefault.a} and neither appears in {@code fipsprov.c}.
 * Rather than ship bridge code that could only ever fail, Jostle keeps them off
 * the FIPS interface library altogether — the C lives in nonfips-only
 * {@code kdf_memhard.*} files, and the Java entry points live on
 * {@link MemoryHardKdfNI}, which no FIPS class implements.</p>
 *
 * <p>This replaces the former {@code FIPSScryptLimitTest} and
 * {@code FIPSArgon2LimitTest}, which drove FIPS NI entry points that no longer
 * exist. Their premise — "the FIPS bridge rejects this" — has been superseded
 * by a stronger guarantee: there is no FIPS bridge to reject anything, so the
 * FIPS interface library exports no symbol for a non-approved algorithm.</p>
 *
 * <p>Gated on {@code TEST_FIPS_LIB}; skipped when unset.</p>
 */
public class FIPSMemoryHardKdfAbsenceTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * JCE layer: JSLFIPS registers neither factory, while JSL in the same JVM
     * registers both. The pair proves the absence is a deliberate FIPS-scope
     * decision rather than the algorithms being missing from the build.
     */
    @Test
    public void memoryHardFactoriesAbsentFromJslfipsButPresentOnJsl() throws Exception
    {
        for (String algorithm : new String[]{"SCRYPT", "ARGON2"})
        {
            Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> SecretKeyFactory.getInstance(algorithm, JostleFIPSProvider.PROVIDER_NAME),
                    "JSLFIPS must not register " + algorithm);

            Assertions.assertNotNull(
                    SecretKeyFactory.getInstance(algorithm, JostleProvider.PROVIDER_NAME),
                    "JSL must register " + algorithm);
        }
    }

    /**
     * NI layer: {@code FIPSNISelector} exposes no memory-hard NI at all.
     *
     * <p>This is a compile-time property today — nothing can call a FIPS scrypt
     * or Argon2 entry point because none is declared — so the check is
     * reflective, to catch a future edit that adds one back. If this fails, the
     * FIPS interface library has almost certainly regained bridge code for a
     * non-approved algorithm.</p>
     */
    @Test
    public void fipsNiSelectorExposesNoMemoryHardKdf()
    {
        for (Field field : FIPSNISelector.class.getDeclaredFields())
        {
            Assertions.assertFalse(MemoryHardKdfNI.class.isAssignableFrom(field.getType()),
                    "FIPSNISelector must expose no memory-hard KDF NI, found: " + field.getName());
        }
    }

    /**
     * The base selector DOES expose one — otherwise the test above could pass
     * because the interface had been deleted entirely rather than kept off the
     * FIPS side.
     */
    @Test
    public void baseNiSelectorDoesExposeMemoryHardKdf() throws Exception
    {
        Field field = org.openssl.jostle.jcajce.provider.NISelector.class.getField("MemoryHardKdfNI");
        Assertions.assertTrue(MemoryHardKdfNI.class.isAssignableFrom(field.getType()));
        Assertions.assertNotNull(field.get(null), "the base provider must supply a memory-hard KDF NI");
    }
}
