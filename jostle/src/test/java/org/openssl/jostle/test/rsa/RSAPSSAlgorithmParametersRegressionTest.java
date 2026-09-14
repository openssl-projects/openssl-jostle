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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * REGRESSION TEST for GitHub issue 58 — "Should RSASSA-PSS AlgorithmParameters
 * be registered?".
 *
 * <p>This class pins the exact failures the issue described, and nothing else.
 * The wider behaviour of the new service is covered by
 * {@link RSAPSSAlgorithmParametersTest}, {@link RSAPSSSignatureParametersTest},
 * {@link RSAPSSTlsSchemeAvailabilityTest} and
 * {@link RSAPSSWithoutJdkProvidersTest}; those would survive a partial revert
 * that reopened the issue, so the three cells below are stated separately.
 *
 * <h2>What was broken</h2>
 *
 * <ol>
 *   <li>No {@code AlgorithmParameters} was registered for RSASSA-PSS on either
 *       provider, so the lookup escaped to SunRsaSign — the reporter's
 *       observation — and failed outright where the JDK providers are
 *       absent.</li>
 *   <li>{@code RSAPSSSignatureSpi} never overrode
 *       {@code engineGetParameters()}, so every call reached the throwing
 *       {@code SignatureSpi} default. All 74 registered Signature services
 *       threw {@link UnsupportedOperationException}.</li>
 *   <li>Consequently the JDK's TLS stack, which resolves RSASSA-PSS with no
 *       provider and treats a RuntimeException as absence of support, dropped
 *       all six rsa_pss_* schemes from the ClientHello whenever this provider
 *       sat first. Pinned in {@link RSAPSSTlsSchemeAvailabilityTest}, which
 *       needs its own JVM and so cannot live here.</li>
 * </ol>
 *
 * <p>Each cell fails if the corresponding production line is reverted:
 * removing the {@code addAlgorithmImplementation} for the parameters fails
 * {@link #algorithmParametersResolveToThisProviderAndNotSunRsaSign()};
 * removing {@code RSAPSSSignatureSpi.engineGetParameters} fails
 * {@link #setParameterThenGetParametersDoesNotThrow()}.
 */
public class RSAPSSAlgorithmParametersRegressionTest
{
    private static Provider jsl;

    private static final PSSParameterSpec SPEC =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    @BeforeAll
    public static void setUp()
    {
        jsl = new JostleProvider();
        Security.addProvider(jsl);
    }

    /**
     * The reporter's sentence: "without registering them, lookups for these
     * escape this provider and use SunRSA instead."
     */
    @Test
    public void algorithmParametersResolveToThisProviderAndNotSunRsaSign()
        throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", jsl);
        Assertions.assertSame(jsl, params.getProvider());
        Assertions.assertEquals("JSL", params.getProvider().getName());

        // By name and by OID, both of which a caller uses.
        Assertions.assertEquals("JSL",
                AlgorithmParameters.getInstance("RSASSA-PSS", "JSL").getProvider().getName());
        Assertions.assertEquals("JSL",
                AlgorithmParameters.getInstance("1.2.840.113549.1.1.10", "JSL")
                        .getProvider().getName());

        // And it is a working service, not merely a registered name.
        params.init(SPEC);
        Assertions.assertEquals(54, params.getEncoded().length);
    }

    /**
     * The order the JDK's TLS stack uses, and the call that threw.
     * {@code getParameters()} must return the spec that was set.
     */
    @Test
    public void setParameterThenGetParametersDoesNotThrow()
        throws Exception
    {
        assertSetThenGet(jsl);
    }

    // The FIPS half of this regression lives in the fips package, where
    // FIPSTestUtil is reachable: FIPSSignatureParametersSweepTest
    // .issue58_setParameterThenGetParametersDoesNotThrow. A registration
    // change is a two-provider change and both halves are pinned.

    private static void assertSetThenGet(Provider provider)
        throws Exception
    {
        Signature signature = Signature.getInstance("RSASSA-PSS", provider);
        signature.setParameter(SPEC);

        AlgorithmParameters reported = signature.getParameters();
        Assertions.assertNotNull(reported,
                provider.getName() + ": getParameters() returned null after setParameter");
        Assertions.assertSame(provider, reported.getProvider(),
                provider.getName() + ": parameters came from another provider");

        PSSParameterSpec back = reported.getParameterSpec(PSSParameterSpec.class);
        Assertions.assertEquals("SHA-256", back.getDigestAlgorithm());
        Assertions.assertEquals("MGF1", back.getMGFAlgorithm());
        Assertions.assertEquals("SHA-256",
                ((MGF1ParameterSpec) back.getMGFParameters()).getDigestAlgorithm());
        Assertions.assertEquals(32, back.getSaltLength());
        Assertions.assertEquals(1, back.getTrailerField());

        AlgorithmParameters expected = AlgorithmParameters.getInstance("RSASSA-PSS", provider);
        expected.init(SPEC);
        Assertions.assertTrue(Arrays.areEqual(expected.getEncoded(), reported.getEncoded()),
                provider.getName() + ": the reported encoding is not the spec that was set");
    }

    /**
     * No Signature service may throw here. The defect was provider-wide — 74
     * of 74 — so pinning only the PSS names would let the rest regress.
     */
    @Test
    public void noRegisteredSignatureThrowsFromGetParameters()
        throws Exception
    {
        int checked = 0;
        for (Provider.Service service : jsl.getServices())
        {
            if (!"Signature".equals(service.getType()))
            {
                continue;
            }
            Signature signature = Signature.getInstance(service.getAlgorithm(), jsl);
            try
            {
                signature.getParameters();
            }
            catch (UnsupportedOperationException e)
            {
                Assertions.fail(service.getAlgorithm() + " threw UnsupportedOperationException");
            }
            checked++;
        }
        Assertions.assertTrue(checked >= 40, "vacuity: only " + checked + " services checked");
    }
}
