/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

/**
 * The PQC providers register NIST CSOR / RFC 9814 OID aliases so that an X.509
 * certificate whose SubjectPublicKeyInfo (or signatureAlgorithm) carries the OID
 * resolves to the JSL KeyFactory / Signature rather than falling back to the JDK
 * default (see {@code JSLKeyX509Certificate} and the {@code Prov*} configure
 * methods).
 *
 * <p>These aliases are wired by hand (ML-DSA / ML-KEM) or by a positional
 * {@code algNames[i] -> oids[i]} loop (SLH-DSA), so the failure modes are: a
 * mistyped OID string (alias missing → no service resolves), a wrong arc (e.g.
 * ML-KEM under the {@code .4.3} "sigAlgs" arc instead of the {@code .4.4} "kems"
 * arc), or a shifted positional pairing (OID resolves, but to the WRONG
 * parameter set). All three are silent at runtime and invisible to a positive
 * round-trip test that uses the algorithm <em>name</em>.
 *
 * <p>The assertions read the provider's own {@code Alg.Alias.<type>.<oid>}
 * mapping table — the exact wiring {@code addAlias} writes and {@code getService}
 * resolves through — so every OID's primary-name pairing is checked without
 * per-parameter-set keygen/signing (SLH-DSA "S" variants are slow). A shifted
 * pairing surfaces as a mismatched primary name; a mistyped/wrong-arc OID
 * surfaces as a missing entry. A separate smoke test confirms the aliases are
 * actually constructible via {@code getInstance}. The OID strings are duplicated
 * verbatim from the provider source on purpose: the test is the independent
 * second copy that a single-sided edit must disagree with.
 */
public class PQCOidAliasTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void mldsaOidAliases()
    {
        // NIST CSOR id-ml-dsa-44/65/87 — both KeyFactory and Signature.
        assertAlias("KeyFactory", "2.16.840.1.101.3.4.3.17", "ML-DSA-44");
        assertAlias("KeyFactory", "2.16.840.1.101.3.4.3.18", "ML-DSA-65");
        assertAlias("KeyFactory", "2.16.840.1.101.3.4.3.19", "ML-DSA-87");
        assertAlias("Signature", "2.16.840.1.101.3.4.3.17", "ML-DSA-44");
        assertAlias("Signature", "2.16.840.1.101.3.4.3.18", "ML-DSA-65");
        assertAlias("Signature", "2.16.840.1.101.3.4.3.19", "ML-DSA-87");
    }

    @Test
    public void mlkemOidAliases()
    {
        // RFC 9814 id-alg-ml-kem-* live under the .4.4 "kems" arc, NOT .4.3
        // "sigAlgs"; ML-KEM is a KEM, so KeyFactory only (no Signature).
        assertAlias("KeyFactory", "2.16.840.1.101.3.4.4.1", "ML-KEM-512");
        assertAlias("KeyFactory", "2.16.840.1.101.3.4.4.2", "ML-KEM-768");
        assertAlias("KeyFactory", "2.16.840.1.101.3.4.4.3", "ML-KEM-1024");
    }

    @Test
    public void slhdsaOidAliases()
    {
        // NIST CSOR id-slh-dsa-* (.20..31), in declaration order. Both
        // KeyFactory and Signature, paired positionally in the provider.
        String[] names = {
                "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F",
                "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F",
                "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F",
                "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"
        };
        for (int i = 0; i < names.length; i++)
        {
            String oid = "2.16.840.1.101.3.4.3." + (20 + i);
            assertAlias("KeyFactory", oid, names[i]);
            assertAlias("Signature", oid, names[i]);
        }
    }

    @Test
    public void oidAliasesAreUsableViaGetInstance()
        throws Exception
    {
        // getService resolution (used above) and getInstance resolution share
        // the same alias table, but prove one of each is actually constructible
        // and reports the JSL provider.
        KeyFactory kf = KeyFactory.getInstance("2.16.840.1.101.3.4.3.17", JostleProvider.PROVIDER_NAME);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, kf.getProvider().getName());

        Signature sig = Signature.getInstance("2.16.840.1.101.3.4.3.17", JostleProvider.PROVIDER_NAME);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, sig.getProvider().getName());

        KeyFactory kemKf = KeyFactory.getInstance("2.16.840.1.101.3.4.4.2", JostleProvider.PROVIDER_NAME);
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, kemKf.getProvider().getName());
    }

    private static void assertAlias(String type, String oid, String expectedPrimary)
    {
        Provider p = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Object mapped = p.get("Alg.Alias." + type + "." + oid);
        Assertions.assertNotNull(mapped, type + " has no alias registered under OID " + oid);
        Assertions.assertEquals(expectedPrimary, mapped,
                type + " OID " + oid + " is aliased to the wrong algorithm");
    }
}
