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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

/**
 * Served-surface lock for the families whose presence in JSLFIPS depends on the
 * loaded module - or is unconditional.
 *
 * <p><b>EdDSA is absent unconditionally.</b> No {@code ProvFIPSED} exists, so
 * Ed25519 / Ed448 never resolve through JSLFIPS whatever module is loaded.
 *
 * <p><b>PQC is module-dependent</b>, and this test changed shape on 2026-08-23
 * when support was added. It previously asserted ML-DSA / ML-KEM / SLH-DSA were
 * unconditionally absent, which was correct while 3.1.2 was the only target -
 * that module implements no PQC. The 3.5.x module implements all three, so the
 * families are now registered when, and only when, the module serves them
 * ({@code ProvFIPS{MLDSA,MLKEM,SLHDSA}}, gated on the keymgmt fetch). Asserting
 * unconditional absence now would codify a stale premise and hide a working
 * algorithm being dropped.
 *
 * <p>So PQC is asserted as an <b>iff</b>: absent exactly when the module cannot
 * fetch it, present otherwise - and all-or-nothing per family, since a partial
 * registration is a real defect rather than a capability. The functional half
 * lives in {@code FIPSPQCTest}.
 *
 * <p>For every name asserted absent, {@code getInstance(name, JSL)} must still
 * resolve in the same JVM - proving the absence is the FIPS module's limit and
 * not a Jostle-wide regression. Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSPQCAbsenceTest
{
    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * Resolve {@code name} of the given JCE service {@code type} through
     * {@code provider}. Mirrors the per-type {@code getInstance} entry points
     * that JSL/JSLFIPS expose for these families.
     */
    private static Object getInstance(String type, String name, String provider)
        throws Exception
    {
        switch (type)
        {
        case "KeyPairGenerator":
            return KeyPairGenerator.getInstance(name, provider);
        case "KeyGenerator":
            return KeyGenerator.getInstance(name, provider);
        case "KeyFactory":
            return KeyFactory.getInstance(name, provider);
        case "Signature":
            return Signature.getInstance(name, provider);
        case "Cipher":
            return Cipher.getInstance(name, provider);
        default:
            throw new IllegalArgumentException("unhandled service type " + type);
        }
    }

    /**
     * Lock a single (type, name) pair: absent from JSLFIPS, present in JSL.
     */
    private static void assertAbsentFromJslfipsButServedByJsl(String type, String name)
        throws Exception
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> getInstance(type, name, JostleFIPSProvider.PROVIDER_NAME),
                type + " " + name + " must not resolve through JSLFIPS");

        Assertions.assertNotNull(getInstance(type, name, JostleProvider.PROVIDER_NAME),
                type + " " + name + " must resolve through JSL");
    }

    /**
     * Every PQC name resolves through JSLFIPS iff the module serves the family,
     * and every name in a family agrees with the rest.
     */
    @Test
    public void pqcAlgorithmsServedIffModuleImplementsThem()
        throws Exception
    {
        assertFamilyIff("ML-DSA-65",
                new String[][]{
                        {"KeyPairGenerator", "MLDSA"}, {"KeyPairGenerator", "ML-DSA-44"},
                        {"KeyPairGenerator", "ML-DSA-65"}, {"KeyPairGenerator", "ML-DSA-87"},
                        {"Signature", "MLDSA"}, {"Signature", "ML-DSA-44"},
                        {"Signature", "ML-DSA-65"}, {"Signature", "ML-DSA-87"},
                        {"KeyFactory", "MLDSA"}, {"KeyFactory", "ML-DSA-44"},
                        {"KeyFactory", "ML-DSA-65"}, {"KeyFactory", "ML-DSA-87"},
                });

        assertFamilyIff("ML-KEM-768",
                new String[][]{
                        {"KeyPairGenerator", "MLKEM"}, {"KeyPairGenerator", "ML-KEM-512"},
                        {"KeyPairGenerator", "ML-KEM-768"}, {"KeyPairGenerator", "ML-KEM-1024"},
                        {"KeyGenerator", "MLKEM"}, {"KeyGenerator", "ML-KEM-512"},
                        {"KeyGenerator", "ML-KEM-768"}, {"KeyGenerator", "ML-KEM-1024"},
                        {"KeyFactory", "MLKEM"}, {"KeyFactory", "ML-KEM-512"},
                        {"KeyFactory", "ML-KEM-768"}, {"KeyFactory", "ML-KEM-1024"},
                        {"Cipher", "MLKEM"}, {"Cipher", "ML-KEM"},
                });

        assertFamilyIff("SLH-DSA-SHA2-128S",
                new String[][]{
                        {"KeyPairGenerator", "SLHDSA"}, {"KeyPairGenerator", "SLH-DSA-SHA2-128S"},
                        {"KeyFactory", "SLHDSA"}, {"KeyFactory", "SLH-DSA-SHA2-128S"},
                        {"Signature", "SLHDSA"}, {"Signature", "SLH-DSA-PURE"},
                        {"Signature", "SLH-DSA-NONE"}, {"Signature", "SLH-DSA-SHA2-128S"},
                });
    }

    /**
     * One family: every {type, name} is present iff the module fetches
     * {@code probeName}, and JSL serves all of them regardless.
     * <p>
     * The all-or-nothing part is the point - a partial registration
     * (KeyFactory present, Signature absent) is a defect a single-name check
     * would miss.
     */
    private static void assertFamilyIff(String probeName, String[][] services)
        throws Exception
    {
        boolean served = FIPSNISelector.OpenSSLFIPSNI
                .canFetch(OpenSSLFIPSNI.OP_KEYMGMT, probeName) != 0;

        for (String[] svc : services)
        {
            Assertions.assertNotNull(getInstance(svc[0], svc[1], JostleProvider.PROVIDER_NAME),
                    svc[0] + " " + svc[1] + " must resolve through JSL");

            if (served)
            {
                Assertions.assertNotNull(
                        getInstance(svc[0], svc[1], JostleFIPSProvider.PROVIDER_NAME),
                        svc[0] + " " + svc[1] + " must resolve through JSLFIPS: the module ("
                                + FIPSNISelector.OpenSSLFIPSNI.moduleVersion() + ") serves "
                                + probeName);
            }
            else
            {
                Assertions.assertThrows(NoSuchAlgorithmException.class,
                        () -> getInstance(svc[0], svc[1], JostleFIPSProvider.PROVIDER_NAME),
                        svc[0] + " " + svc[1] + " must not resolve through JSLFIPS: the module ("
                                + FIPSNISelector.OpenSSLFIPSNI.moduleVersion() + ") cannot fetch "
                                + probeName);
            }
        }
    }

    @Test
    public void eddsaAlgorithmsAbsentFromJslfips()
        throws Exception
    {
        // ProvED registers no FIPS counterpart: the 3.1.2 module does not
        // approve FIPS 186-5 EdDSA. KeyPairGenerator / KeyFactory carry the
        // bare "ED" name (with "EDDSA" alias) plus the curve names; Signature
        // carries "EDDSA" as a primary name plus the curve names.
        for (String name : new String[]{"ED", "EDDSA", "ED25519", "ED448"})
        {
            assertAbsentFromJslfipsButServedByJsl("KeyPairGenerator", name);
            assertAbsentFromJslfipsButServedByJsl("KeyFactory", name);
        }
        for (String name : new String[]{"EDDSA", "ED25519", "ED448"})
        {
            assertAbsentFromJslfipsButServedByJsl("Signature", name);
        }
    }
}
