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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * The FIPS twin of {@code SignatureParametersSweepTest}.
 *
 * <p>A registration change is a two-provider change, and the base sweep reads
 * {@code JostleProvider.getServices()} — it is structurally blind to anything
 * registered only in JSLFIPS, and to a FIPS registration that was missed. The
 * gated surface differs per module, so the sweep enumerates rather than
 * comparing against a fixed list.
 */
public class FIPSSignatureParametersSweepTest
{
    private static final int MINIMUM_SIGNATURE_SERVICES = 20;

    private Provider provider;

    /**
     * Gate in a before-hook so it fails CLOSED: a per-method gate lets a
     * class run its body when the hook is skipped.
     */
    @BeforeEach
    public void requireFipsModule()
    {
        provider = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyRegisteredFipsSignatureAnswersGetParameters()
        throws Exception
    {
        TreeSet<String> names = new TreeSet<String>();
        for (Provider.Service service : provider.getServices())
        {
            if ("Signature".equals(service.getType()))
            {
                names.add(service.getAlgorithm());
            }
        }
        Assertions.assertTrue(names.size() >= MINIMUM_SIGNATURE_SERVICES,
                "vacuity: only " + names.size() + " FIPS Signature services enumerated");

        List<String> threw = new ArrayList<String>();
        List<String> reportedParameters = new ArrayList<String>();
        for (String name : names)
        {
            Signature signature = Signature.getInstance(name, provider);
            AlgorithmParameters params;
            try
            {
                params = signature.getParameters();
            }
            catch (UnsupportedOperationException e)
            {
                threw.add(name);
                continue;
            }
            if (params != null)
            {
                reportedParameters.add(name);
                Assertions.assertSame(provider, params.getProvider(),
                        name + " resolved its parameters through another provider");
            }
        }

        Assertions.assertEquals(new ArrayList<String>(), threw,
                "these JSLFIPS Signature services still throw from getParameters()");
        Assertions.assertFalse(reportedParameters.isEmpty(),
                "no JSLFIPS Signature reported parameters");
    }

    /**
     * REGRESSION, GitHub issue 58, FIPS half. The base half is
     * {@code RSAPSSAlgorithmParametersRegressionTest}; it cannot reach
     * {@link FIPSTestUtil}, which is package-private here. Both are pinned
     * because a registration change is a two-provider change and JSLFIPS
     * shares the Signature SPI whose missing override caused the defect.
     */
    @Test
    public void issue58_setParameterThenGetParametersDoesNotThrow()
        throws Exception
    {
        PSSParameterSpec spec =
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        Signature signature = Signature.getInstance("RSASSA-PSS", provider);
        signature.setParameter(spec);

        AlgorithmParameters reported = signature.getParameters();
        Assertions.assertNotNull(reported, "getParameters() returned null after setParameter");
        Assertions.assertSame(provider, reported.getProvider(),
                "parameters came from another provider");

        PSSParameterSpec back = reported.getParameterSpec(PSSParameterSpec.class);
        Assertions.assertEquals("SHA-256", back.getDigestAlgorithm());
        Assertions.assertEquals(32, back.getSaltLength());
        Assertions.assertEquals(1, back.getTrailerField());

        Assertions.assertEquals(provider.getName(),
                AlgorithmParameters.getInstance("1.2.840.113549.1.1.10", provider)
                        .getProvider().getName());
    }

    @Test
    public void fipsPssParametersRoundTripThroughTheFipsProvider()
        throws Exception
    {
        PSSParameterSpec spec =
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", provider);
        params.init(spec);
        byte[] der = params.getEncoded();

        // Same wire form as the base provider and as both references.
        Assertions.assertEquals(54, der.length);

        AlgorithmParameters back = AlgorithmParameters.getInstance("RSASSA-PSS", provider);
        back.init(der);
        PSSParameterSpec decoded = back.getParameterSpec(PSSParameterSpec.class);
        Assertions.assertEquals("SHA-256", decoded.getDigestAlgorithm());
        Assertions.assertEquals(32, decoded.getSaltLength());
        Assertions.assertEquals(1, decoded.getTrailerField());
    }
}
