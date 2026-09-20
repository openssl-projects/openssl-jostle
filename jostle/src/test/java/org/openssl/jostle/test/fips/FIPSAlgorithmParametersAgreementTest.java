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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.util.AlgorithmParametersSurfaceDriver;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.util.SortedSet;

/**
 * JSLFIPS's {@code AlgorithmParameters} codecs against BouncyCastle and
 * against JSL.
 *
 * <p>The base twin is {@code AlgorithmParametersAgreementTest}. Neither
 * substitutes for the other: the codecs are pure-Java ASN.1 and shared by both
 * registrars, so what differs is WHICH names each provider registers, and that
 * is the thing a single-provider guard cannot see.
 */
public class FIPSAlgorithmParametersAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();

        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Every {@code AlgorithmParameters} name JSLFIPS registers is DRIVEN,
     * discovered rather than listed, aliases included.
     */
    @Test
    public void everyRegisteredAlgorithmParametersIsDriven()
    {
        Provider fips = Security.getProvider(FIPS);

        ProviderSurfaceGuard.assertEveryServiceDriven(
                fips, AlgorithmParametersSurfaceDriver.PREFIX, "AlgorithmParameters (JSLFIPS)",
                new String[]{"AlgorithmParameters"},
                AlgorithmParametersSurfaceDriver.forProvider(FIPS));
    }

    /**
     * A name both providers register encodes byte-identically through each.
     *
     * <p>The codecs are shared Java, so this holds by construction — which is
     * the reason to assert it: nothing else would notice one registrar wired
     * to a different codec class.
     */
    @Test
    public void everySharedNameEncodesIdenticallyThroughBothProviders() throws Exception
    {
        Provider fips = Security.getProvider(FIPS);
        Provider jsl = Security.getProvider(JSL);

        SortedSet<String> shared = new java.util.TreeSet<String>(
                ProviderSurfaceGuard.registeredSurface(fips,
                        AlgorithmParametersSurfaceDriver.PREFIX,
                        new String[]{"AlgorithmParameters"}));
        shared.retainAll(ProviderSurfaceGuard.registeredSurface(jsl,
                AlgorithmParametersSurfaceDriver.PREFIX,
                new String[]{"AlgorithmParameters"}));

        Assertions.assertFalse(shared.isEmpty(),
                "no name is registered by both providers, so this compared nothing");

        for (String entry : shared)
        {
            String alg = entry.substring("AlgorithmParameters.".length());
            Assertions.assertTrue(
                    Arrays.areEqual(AlgorithmParametersSurfaceDriver.encodeThrough(FIPS, alg),
                            AlgorithmParametersSurfaceDriver.encodeThrough(JSL, alg)),
                    alg + ": the two providers encode the same spec differently");
            Assertions.assertEquals(
                    jsl.getService("AlgorithmParameters", alg).getClassName(),
                    fips.getService("AlgorithmParameters", alg).getClassName(),
                    alg + ": the two providers resolve this name to different codec classes");
        }
    }

    /**
     * JSLFIPS's registration agrees with the module, both directions, over the
     * WHOLE surface rather than a list of primaries.
     *
     * <p>Per NAME, not per SPI class: the absent families share
     * {@code IvAlgorithmParameters} with AES and Triple-DES, which the module
     * does serve, so the class is registered either way and only the name
     * carries the answer.
     */
    @Test
    public void algorithmParametersRegistrationAgreesWithTheModule()
    {
        Provider fips = Security.getProvider(FIPS);
        Provider jsl = Security.getProvider(JSL);

        String[][] rows = {
                {"ARIA", "ARIA-128-CBC"},
                {"CAMELLIA", "CAMELLIA-128-CBC"},
                {"SM4", "SM4-CBC"},
                {"CHACHA20-POLY1305", "ChaCha20-Poly1305"},
                {"AES", "AES-128-CBC"},
                {"DESEDE", "DES-EDE3-CBC"},
                {"GCM", "AES-128-GCM"},
                {"CCM", "AES-128-CCM"},
        };

        SortedSet<String> jslSurface = ProviderSurfaceGuard.registeredSurface(
                jsl, AlgorithmParametersSurfaceDriver.PREFIX,
                new String[]{"AlgorithmParameters"});
        SortedSet<String> fipsSurface = ProviderSurfaceGuard.registeredSurface(
                fips, AlgorithmParametersSurfaceDriver.PREFIX,
                new String[]{"AlgorithmParameters"});

        // (a) every JSL name whose PRIMARY is a row, alias spellings included.
        for (String[] row : rows)
        {
            boolean served = FIPSTestUtil.moduleServesCipher(row[1]);
            int reached = 0;
            for (String entry : jslSurface)
            {
                String alg = entry.substring("AlgorithmParameters.".length());
                if (!row[0].equalsIgnoreCase(primaryOf(jsl, alg)))
                {
                    continue;
                }
                reached++;
                Assertions.assertEquals(served, fipsSurface.contains(entry),
                        alg + " (primary " + row[0] + "): the module "
                                + (served ? "serves " : "does not serve ") + row[1]
                                + ", so JSLFIPS must " + (served ? "register" : "not register")
                                + " it");
            }
            Assertions.assertTrue(reached > 0,
                    row[0] + ": no registered name has this primary, so the row measured nothing");
        }

        // (b) nothing absent is unexplained.
        SortedSet<String> absent = new java.util.TreeSet<String>(jslSurface);
        absent.removeAll(fipsSurface);
        for (String entry : absent)
        {
            String alg = entry.substring("AlgorithmParameters.".length());
            String primary = primaryOf(jsl, alg);
            String cipher = null;
            for (String[] row : rows)
            {
                if (row[0].equalsIgnoreCase(primary))
                {
                    cipher = row[1];
                }
            }
            Assertions.assertNotNull(cipher,
                    alg + " is absent from JSLFIPS and no row explains why");
            Assertions.assertFalse(FIPSTestUtil.moduleServesCipher(cipher),
                    alg + " is absent from JSLFIPS although the module serves " + cipher);
        }
    }

    /**
     * The primary an alias resolves to, read from the provider's own
     * {@code Alg.Alias.*} entries.
     *
     * <p>NOT from {@code getService(type, alias).getAlgorithm()}:
     * {@code JostleProvider.getService} is custom and answers with the name it
     * was ASKED for, so an alias reports itself and every alias would look like
     * a primary nothing explains.
     */
    private static String primaryOf(Provider p, String alg)
    {
        Object target = p.get("Alg.Alias.AlgorithmParameters." + alg);
        return target == null ? alg : String.valueOf(target);
    }
}
