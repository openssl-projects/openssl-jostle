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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

/**
 * Served-surface lock: the FIPS provider ("JSLFIPS") registers NO post-quantum
 * (ML-DSA / ML-KEM / SLH-DSA) or EdDSA (Ed25519 / Ed448) services. The FIPS
 * module Jostle validates against is OpenSSL 3.1.2, which predates FIPS 186-5
 * EdDSA and the NIST PQC standards, so {@code JostleFIPSProvider.setup()} wires
 * none of {@code ProvMLDSA}/{@code ProvMLKEM}/{@code ProvSLHDSA}/{@code ProvED}.
 *
 * <p>For every name the non-FIPS provider (JSL) registers in these families,
 * {@code getInstance(name, JSLFIPS)} must throw {@link NoSuchAlgorithmException}
 * while {@code getInstance(name, JSL)} still resolves in the same JVM. This
 * guards against accidental registration of a non-approved algorithm through the
 * FIPS surface. Mirrors the absence-lock shape of
 * {@code FIPSXDHKDFTest.xdhIsAbsentFromJslfips}. Gated on TEST_FIPS_LIB; skipped
 * when unset.
 */
public class FIPSPQCAbsenceTest
{
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

    @Test
    public void pqcAlgorithmsAbsentFromJslfips()
        throws Exception
    {
        ensureProviders();

        // ML-DSA: KeyPairGenerator / Signature / KeyFactory (ProvMLDSA).
        for (String name : new String[]{"MLDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
        {
            assertAbsentFromJslfipsButServedByJsl("KeyPairGenerator", name);
            assertAbsentFromJslfipsButServedByJsl("Signature", name);
            assertAbsentFromJslfipsButServedByJsl("KeyFactory", name);
        }

        // ML-KEM: KeyPairGenerator / KeyGenerator / KeyFactory (ProvMLKEM).
        for (String name : new String[]{"MLKEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
        {
            assertAbsentFromJslfipsButServedByJsl("KeyPairGenerator", name);
            assertAbsentFromJslfipsButServedByJsl("KeyGenerator", name);
            assertAbsentFromJslfipsButServedByJsl("KeyFactory", name);
        }

        // ML-KEM KTS Cipher: registered only under the bare family names
        // (ProvMLKEM registers "ML-KEM" + alias "MLKEM"; no per-variant Cipher).
        for (String name : new String[]{"MLKEM", "ML-KEM"})
        {
            assertAbsentFromJslfipsButServedByJsl("Cipher", name);
        }

        // SLH-DSA: KeyPairGenerator / KeyFactory (bare family + a representative
        // parameter set) and Signature (bare family + PURE/NONE + a variant).
        for (String name : new String[]{"SLHDSA", "SLH-DSA-SHA2-128S"})
        {
            assertAbsentFromJslfipsButServedByJsl("KeyPairGenerator", name);
            assertAbsentFromJslfipsButServedByJsl("KeyFactory", name);
        }
        for (String name : new String[]{"SLHDSA", "SLH-DSA-PURE", "SLH-DSA-NONE", "SLH-DSA-SHA2-128S"})
        {
            assertAbsentFromJslfipsButServedByJsl("Signature", name);
        }
    }

    @Test
    public void eddsaAlgorithmsAbsentFromJslfips()
        throws Exception
    {
        ensureProviders();

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
