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

package org.openssl.jostle.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.opentest4j.AssertionFailedError;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Every primary, non-OID service name JSL registers is exercised by at least one worked example; the rule is
 * {@link ExamplesCoverage}. The JSLFIPS half is {@code FIPSExamplesCoverageTest}.
 */
public class ExamplesCoverageTest
{
    /**
     * JSL service types whose examples have not landed yet. Shrinks commit by commit and is empty at the end;
     * a pending type whose own examples class credits any of its names fails, so an entry cannot outlive its
     * reason.
     */
    private static final Set<String> JSL_PENDING = new TreeSet<String>(Arrays.asList(
            "AlgorithmParameterGenerator", "AlgorithmParameters", "CertPathBuilder", "CertPathValidator",
            "CertificateFactory", "Cipher", "KeyAgreement", "KeyFactory", "KeyGenerator", "KeyPairGenerator",
            "KeyStore", "Signature"));

    @Test
    public void everyJslServiceHasAnExample()
            throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        ExamplesCoverage.check("jsl", Security.getProvider(JostleProvider.PROVIDER_NAME), JSL_PENDING);
    }

    /**
     * The matcher credits what it should and nothing else: a literal, a looped list, an alias and a
     * transformation each credit their primary, while a name in a list with no looping getInstance credits
     * nothing.
     */
    @Test
    public void theMatcherCreditsOnlyWhatAnExampleCalls()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        Provider p = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Map<String, Set<String>> got = ExamplesCoverage.credit(Arrays.asList(
                "MessageDigest.getInstance(\"SHA-256\", \"JSL\");",
                "String[] names = {\"HMACSHA1\", \"HmacSHA256\"};",
                "for (String name : names) { Mac.getInstance(name, \"JSL\"); }",
                "Cipher.getInstance(\"AES/GCM/NoPadding\", \"JSL\");",
                "Cipher.getInstance(\"AES/CCM/NoPadding\", \"JSL\");"), p);
        Assertions.assertEquals(new TreeSet<String>(Collections.singletonList("SHA2-256")),
                got.get("MessageDigest"));
        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("HMACSHA1", "HMACSHA256")), got.get("Mac"));
        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("AES", "AES/CCM/NOPADDING")),
                got.get("Cipher"));

        Map<String, Set<String>> none = ExamplesCoverage.credit(Arrays.asList(
                "String[] names = {\"HMACSHA1\"};",
                "Mac.getInstance(\"HMACSHA256\", \"JSL\");"), p);
        Assertions.assertEquals(new TreeSet<String>(Collections.singletonList("HMACSHA256")), none.get("Mac"));
    }

    /**
     * A pending type credited only through another type's class stays pending, and the same credit from its
     * own class fails. Every registered type is pending here, so nothing else is checked.
     */
    @Test
    public void aPendingTypeFailsOnlyOnItsOwnClass()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        Provider p = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Set<String> allPending = new TreeSet<String>();
        for (Provider.Service s : p.getServices())
        {
            allPending.add(s.getType());
        }
        List<String> body = Collections.singletonList("KeyPairGenerator.getInstance(\"RSA\", \"JSL\");");
        ExamplesCoverage.check("jsl", p, allPending, Collections.singletonList(exampleClass("Cipher", body)));

        AssertionFailedError e = Assertions.assertThrows(AssertionFailedError.class, () ->
                ExamplesCoverage.check("jsl", p, allPending,
                        Collections.singletonList(exampleClass("KeyPairGenerator", body))));
        Assertions.assertTrue(e.getMessage().contains(
                "pending type KeyPairGenerator has examples in its own class [RSA]"), e.getMessage());
    }

    private static ExamplesGuide.ExampleClass exampleClass(String section, List<String> body)
    {
        ExamplesGuide.Method m = new ExamplesGuide.Method("example", false,
                Collections.singletonList("An example."), body);
        return new ExamplesGuide.ExampleClass("jsl", section + "ExamplesTest",
                Collections.singletonList("A section."), Collections.<String>emptyList(),
                Collections.singletonList(m));
    }
}
