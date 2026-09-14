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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/**
 * Every registered Signature answers {@code getParameters()} without throwing.
 *
 * <p>GitHub issue 58. The inherited {@code SignatureSpi.engineGetParameters}
 * throws {@link UnsupportedOperationException}, and no SPI here overrode it —
 * so all 74 registered Signature services threw, where SunRsaSign, SunEC, SUN
 * and BouncyCastle all answer null. The JDK's TLS stack calls this on
 * RSASSA-PSS and treats a RuntimeException as "the providers do not support
 * it", which silently removed every rsa_pss_* scheme from the ClientHello.
 *
 * <p>The sweep is over {@code getServices()} rather than a hand list, so a
 * family registered later is covered the day it lands.
 */
public class SignatureParametersSweepTest
{
    /** Fewer than this means the enumeration broke, not that the provider shrank. */
    private static final int MINIMUM_SIGNATURE_SERVICES = 40;

    @Test
    public void everyRegisteredSignatureAnswersGetParameters()
        throws Exception
    {
        Provider provider = new JostleProvider();

        TreeSet<String> names = new TreeSet<String>();
        for (Provider.Service service : provider.getServices())
        {
            if ("Signature".equals(service.getType()))
            {
                names.add(service.getAlgorithm());
            }
        }
        Assertions.assertTrue(names.size() >= MINIMUM_SIGNATURE_SERVICES,
                "vacuity: only " + names.size() + " Signature services enumerated");

        List<String> threw = new ArrayList<String>();
        List<String> pss = new ArrayList<String>();
        List<String> plain = new ArrayList<String>();
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
            if (params == null)
            {
                plain.add(name);
            }
            else
            {
                pss.add(name);
                Assertions.assertSame(provider, params.getProvider(),
                        name + " resolved its parameters through another provider");
            }
        }

        Assertions.assertEquals(new ArrayList<String>(), threw,
                "these Signature services still throw from getParameters()");
        // A PSS name is one that carries parameters; everything else reports
        // none, as every reference provider does.
        Assertions.assertFalse(pss.isEmpty(), "no Signature reported parameters");
        Assertions.assertFalse(plain.isEmpty(), "no Signature reported null");
        for (String name : pss)
        {
            Assertions.assertTrue(name.contains("PSS") || name.contains("MGF1"),
                    name + " reports parameters but is not a PSS name");
        }
    }

    /**
     * The non-PSS answer is null, which is what SunRsaSign, SunEC, SUN and
     * BouncyCastle all return — measured. Asserting against a live reference
     * rather than against our own expectation, so a JDK change is visible.
     */
    @Test
    public void nullMatchesWhatTheReferenceProvidersReturn()
        throws Exception
    {
        String[][] references = {
                {"SunRsaSign", "SHA256withRSA"},
                {"SunEC", "SHA256withECDSA"},
                {"SUN", "SHA256withDSA"},
        };
        for (String[] reference : references)
        {
            Signature signature = Signature.getInstance(reference[1], reference[0]);
            Assertions.assertNull(signature.getParameters(),
                    reference[0] + "/" + reference[1] + " no longer returns null");
        }

        Provider provider = new JostleProvider();
        Assertions.assertNull(Signature.getInstance("SHA256withRSA", provider).getParameters());
        Assertions.assertNull(Signature.getInstance("SHA256withECDSA", provider).getParameters());
        Assertions.assertNull(Signature.getInstance("SHA256withDSA", provider).getParameters());
    }
}
