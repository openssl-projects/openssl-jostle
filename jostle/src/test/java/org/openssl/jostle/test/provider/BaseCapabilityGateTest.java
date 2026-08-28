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
import org.openssl.jostle.jcajce.provider.OpenSSLNI;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * The base provider's PQC registration gate: JSL registers ML-KEM, ML-DSA,
 * SLH-DSA and the four TLS hybrid groups only when the linked libcrypto can
 * actually serve them (they need OpenSSL 3.5 or later).
 *
 * <p><b>Coverage limit, stated rather than left to be discovered.</b> Both
 * mainline installs on hand (3.5.8, the build target, and 3.6.2) serve every
 * gated name, so the gate's ABSENT arm does not execute and no available
 * configuration makes it.
 * What these tests can and do establish is that the probe discriminates, that
 * registration tracks it exactly, and that a family is all-or-nothing. End to
 * end usability of the registered services is the per-family suites'
 * ({@code MLKEMTest}, {@code MLDSATest}, {@code SLHDSATest},
 * {@code MLXKEMAgreementTest}); this class only adds that every registered
 * service of a gated family is constructible both ways.
 */
public class BaseCapabilityGateTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    /**
     * Gated family to the keymgmt name its registration is decided by. The
     * first three gate the whole family on one representative name, as the
     * FIPS twins do; the hybrids gate per variant and are added below.
     *
     * <p>Stated here independently of the {@code Prov*} classes on purpose:
     * two declarations, so a changed gate name fails rather than agreeing
     * with itself.
     */
    private static final Map<String, String> FAMILY_GATE = new LinkedHashMap<String, String>();

    /** Algorithm-name prefixes that belong to each gated family. */
    private static final Map<String, List<String>> FAMILY_PREFIXES = new LinkedHashMap<String, List<String>>();

    static
    {
        FAMILY_GATE.put("ML-KEM", "ML-KEM-768");
        FAMILY_GATE.put("ML-DSA", "ML-DSA-65");
        FAMILY_GATE.put("SLH-DSA", "SLH-DSA-SHA2-128S");

        FAMILY_PREFIXES.put("ML-KEM", Arrays.asList("ML-KEM", "MLKEM"));
        FAMILY_PREFIXES.put("ML-DSA", Arrays.asList("ML-DSA", "MLDSA"));
        FAMILY_PREFIXES.put("SLH-DSA", Arrays.asList("SLH-DSA", "SLHDSA", "DET-SLH-DSA"));

        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            FAMILY_GATE.put(spec.getName(), spec.getName());
            FAMILY_PREFIXES.put(spec.getName(), Arrays.asList(spec.getName()));
        }
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The gate is only worth anything if the probe can say no. It must
     * discriminate on BOTH arguments, so a stub returning a constant fails
     * whichever constant it picks.
     */
    @Test
    public void theProbeDiscriminatesOnNameAndOnOpType()
    {
        OpenSSLNI ni = TestNISelector.getOpenSSLNI();

        // Says no to a name nothing implements.
        Assertions.assertEquals(0, ni.canFetch(OpenSSLNI.OP_KEYMGMT, "NO-SUCH-ALGORITHM-BaseCapabilityGateTest"));

        // Says no to a REAL name under the wrong operation type. This is the
        // discriminating control: an ML-KEM key type exists, an ML-KEM cipher
        // does not, so the answer cannot come from name recognition alone.
        Assertions.assertEquals(1, ni.canFetch(OpenSSLNI.OP_KEYMGMT, "ML-KEM-768"));
        Assertions.assertEquals(0, ni.canFetch(OpenSSLNI.OP_CIPHER, "ML-KEM-768"));

        // And yes to a name that really is a cipher, so the op type is not
        // simply always refused.
        Assertions.assertEquals(1, ni.canFetch(OpenSSLNI.OP_CIPHER, "AES-256-CBC"));
    }

    /**
     * Registration tracks the probe exactly, and a family is all-or-nothing:
     * a partial gate — KeyFactory registered, KeyPairGenerator not — is a real
     * defect that checking one service would miss.
     */
    @Test
    public void everyGatedFamilyIsRegisteredIffTheProbeAllowsIt()
    {
        Provider p = Security.getProvider(JSL);
        OpenSSLNI ni = TestNISelector.getOpenSSLNI();
        List<String> failures = new ArrayList<String>();

        for (Map.Entry<String, String> e : FAMILY_GATE.entrySet())
        {
            String family = e.getKey();
            boolean allowed = ni.canFetch(OpenSSLNI.OP_KEYMGMT, e.getValue()) != 0;
            TreeSet<String> services = servicesOf(p, FAMILY_PREFIXES.get(family));

            if (allowed && services.isEmpty())
            {
                failures.add(family + ": probe says the module serves " + e.getValue()
                        + " but nothing is registered");
            }
            if (!allowed && !services.isEmpty())
            {
                failures.add(family + ": probe says " + e.getValue()
                        + " is unavailable but these are registered " + services);
            }
        }

        Assertions.assertTrue(failures.isEmpty(), String.join("\n", failures));

        // Non-vacuity: on every supported libcrypto all seven gates open, so a
        // run in which none did would pass the loop above having compared
        // nothing.
        int open = 0;
        for (String gateName : FAMILY_GATE.values())
        {
            if (ni.canFetch(OpenSSLNI.OP_KEYMGMT, gateName) != 0)
            {
                open++;
            }
        }
        Assertions.assertTrue(open > 0,
                "no gated family is available at all; the gate was not exercised");
    }

    /**
     * Registration is not usability. Every registered service of a gated
     * family must construct through {@code Service.newInstance} AND through
     * the ordinary JCE lookup — the two disagree when a class name or an alias
     * is wrong.
     */
    @Test
    public void everyRegisteredGatedServiceIsConstructible()
    {
        Provider p = Security.getProvider(JSL);
        List<String> failures = new ArrayList<String>();
        int checked = 0;

        for (Provider.Service s : p.getServices())
        {
            if (!belongsToAGatedFamily(s.getAlgorithm()))
            {
                continue;
            }
            checked++;
            try
            {
                Assertions.assertNotNull(s.newInstance(null),
                        s.getType() + "." + s.getAlgorithm() + " newInstance returned null");
            }
            catch (Throwable t)
            {
                failures.add(s.getType() + "." + s.getAlgorithm() + " newInstance: " + t);
            }
            try
            {
                Assertions.assertNotNull(jceLookup(s.getType(), s.getAlgorithm()),
                        s.getType() + "." + s.getAlgorithm() + " getInstance returned null");
            }
            catch (Throwable t)
            {
                failures.add(s.getType() + "." + s.getAlgorithm() + " getInstance: " + t);
            }
        }

        Assertions.assertTrue(failures.isEmpty(), String.join("\n", failures));
        Assertions.assertTrue(checked > 0, "no gated service was checked");
    }

    private static Object jceLookup(String type, String alg) throws Exception
    {
        if ("KeyPairGenerator".equals(type))
        {
            return java.security.KeyPairGenerator.getInstance(alg, JSL);
        }
        if ("KeyGenerator".equals(type))
        {
            return javax.crypto.KeyGenerator.getInstance(alg, JSL);
        }
        if ("KeyFactory".equals(type))
        {
            return java.security.KeyFactory.getInstance(alg, JSL);
        }
        if ("Signature".equals(type))
        {
            return java.security.Signature.getInstance(alg, JSL);
        }
        if ("Cipher".equals(type))
        {
            return javax.crypto.Cipher.getInstance(alg, JSL);
        }
        throw new IllegalStateException("unhandled service type " + type
                + " for " + alg + "; teach jceLookup about it rather than skipping it");
    }

    private static boolean belongsToAGatedFamily(String algorithm)
    {
        for (List<String> prefixes : FAMILY_PREFIXES.values())
        {
            if (matches(algorithm, prefixes))
            {
                return true;
            }
        }
        return false;
    }

    private static TreeSet<String> servicesOf(Provider p, List<String> prefixes)
    {
        TreeSet<String> out = new TreeSet<String>();
        for (Provider.Service s : p.getServices())
        {
            if (matches(s.getAlgorithm(), prefixes))
            {
                out.add(s.getType() + "." + s.getAlgorithm());
            }
        }
        return out;
    }

    private static boolean matches(String algorithm, List<String> prefixes)
    {
        String upper = algorithm.toUpperCase(Locale.ROOT);
        for (String prefix : prefixes)
        {
            if (upper.startsWith(prefix.toUpperCase(Locale.ROOT)))
            {
                return true;
            }
        }
        return false;
    }
}
