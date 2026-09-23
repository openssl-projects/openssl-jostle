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

package org.openssl.jostle.test.cache;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A native fact is cached per NI instance, so one instance never answers for
 * another. Each row builds two FRESH instances by reflection, so no earlier
 * test can have warmed them, and probes through the first, the second, then
 * the second again: the probe counts must go 1/0, 1/1, 1/1 and both instances
 * must report the same value.
 *
 * <p>Here both instances are the base library's, which proves the binding is
 * per instance. The FIPS twin pairs a base instance with a FIPS one, which is
 * the binding that matters: a fact one module reports never answers for the
 * other.
 */
public class NativeFactCacheBindingTest
{
    /** The seven interfaces, in the order the table prints them. */
    static final String[] INTERFACES = {"MD", "MAC", "ED", "MLDSA", "SLHDSA", "SPEC", "RAND"};

    private static final String P = "org.openssl.jostle.jcajce.";

    /** Base-library concrete classes: {JNI, FFI}. */
    static final Map<String, String[]> BASE = new LinkedHashMap<String, String[]>();

    /** FIPS-library concrete classes: {JNI, FFI}. */
    protected static final Map<String, String[]> FIPS = new LinkedHashMap<String, String[]>();

    static
    {
        BASE.put("MD", new String[]{P + "provider.md.MDServiceJNI", P + "provider.md.MDServiceFFI"});
        BASE.put("MAC", new String[]{P + "provider.mac.MacServiceJNI", P + "provider.mac.MacServiceFFI"});
        BASE.put("ED", new String[]{P + "provider.ed.EDServiceJNI", P + "provider.ed.EdDSAServiceFFI"});
        BASE.put("MLDSA", new String[]{P + "provider.mldsa.MLDSAServiceJNI", P + "provider.mldsa.MLDSAServiceFFI"});
        BASE.put("SLHDSA", new String[]{P + "provider.slhdsa.SLHDSAServiceJNI",
                P + "provider.slhdsa.SLHDSAServiceFFI"});
        BASE.put("SPEC", new String[]{P + "spec.SpecJNI", P + "spec.SpecFFI"});
        BASE.put("RAND", new String[]{P + "provider.rand.RandServiceJNI", P + "provider.rand.RandServiceFFI"});

        String f = P + "provider.fips.";
        FIPS.put("MD", new String[]{f + "MDServiceFIPSJNI", f + "MDServiceFIPSFFI"});
        FIPS.put("MAC", new String[]{f + "MacServiceFIPSJNI", f + "MacServiceFIPSFFI"});
        FIPS.put("ED", new String[]{f + "EDServiceFIPSJNI", f + "EDServiceFIPSFFI"});
        FIPS.put("MLDSA", new String[]{f + "MLDSAServiceFIPSJNI", f + "MLDSAServiceFIPSFFI"});
        FIPS.put("SLHDSA", new String[]{f + "SLHDSAServiceFIPSJNI", f + "SLHDSAServiceFIPSFFI"});
        FIPS.put("SPEC", new String[]{f + "SpecFIPSJNI", f + "SpecFIPSFFI"});
        FIPS.put("RAND", new String[]{f + "RandServiceFIPSJNI", f + "RandServiceFIPSFFI"});
    }

    /** The key algorithm each signature or KEM row needs; the rest need none. */
    static final Map<String, String> KEY_ALG = new LinkedHashMap<String, String>();

    static
    {
        KEY_ALG.put("ED", "Ed25519");
        KEY_ALG.put("MLDSA", "ML-DSA-65");
        KEY_ALG.put("SLHDSA", "SLH-DSA-SHA2-128F");
        KEY_ALG.put("SPEC", "ML-KEM-768");
    }

    @BeforeAll
    public static void installBase()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    protected Provider firstProvider()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    protected Provider secondProvider()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    protected Map<String, String[]> secondClasses()
    {
        return BASE;
    }

    protected String pairing()
    {
        return "base-vs-base";
    }

    /** A fresh instance of the bridge this leg runs. */
    static Object fresh(Map<String, String[]> classes, String iface) throws Exception
    {
        String name = classes.get(iface)[Loader.isFFI() ? 1 : 0];
        Constructor<?> c = Class.forName(name).getDeclaredConstructor();
        c.setAccessible(true);
        return c.newInstance();
    }

    static NativeLengthCache<?> cacheOf(Object ni) throws Exception
    {
        Method m = ni.getClass().getMethod("lengthCache");
        m.setAccessible(true);
        return (NativeLengthCache<?>) m.invoke(ni);
    }

    /** One probe of the interface's fact through {@code ni}, with a key made by {@code provider}. */
    static int probe(String iface, Object ni, Provider provider) throws Exception
    {
        if ("MD".equals(iface))
        {
            return ((MDServiceNI) ni).digestOutputLength("SHA2-256");
        }
        if ("MAC".equals(iface))
        {
            MacServiceNI mac = (MacServiceNI) ni;
            long ref = mac.allocateMac("HMAC", "SHA-256");
            try
            {
                return mac.macLength(ref, "HMAC/SHA-256");
            }
            finally
            {
                mac.dispose(ref);
            }
        }
        if ("RAND".equals(iface))
        {
            return ((RandServiceNI) ni).drbgMaxStrength("CTR-DRBG", "AES-256-CTR");
        }

        KeyPair kp = KeyPairGenerator.getInstance(KEY_ALG.get(iface), provider).generateKeyPair();
        PKEYKeySpec priv = ((OSSLKey) kp.getPrivate()).getSpec();
        try
        {
            if ("SPEC".equals(iface))
            {
                PKEYKeySpec pub = ((OSSLKey) kp.getPublic()).getSpec();
                return ((SpecNI) ni).encapsulationLength(pub.getReference(), pub.getType(), 32, TestUtil.RNDSrc);
            }
            if ("ED".equals(iface))
            {
                EDServiceNI ed = (EDServiceNI) ni;
                long ctx = ed.allocateSigner();
                try
                {
                    ed.initSign(ctx, priv.getReference(), priv.getType().getTypeName(), new byte[0], 0,
                            TestUtil.RNDSrc);
                    return ed.signatureLength(ctx, priv.getType(), TestUtil.RNDSrc);
                }
                finally
                {
                    ed.disposeSigner(ctx);
                }
            }
            if ("MLDSA".equals(iface))
            {
                MLDSAServiceNI ml = (MLDSAServiceNI) ni;
                long ctx = ml.allocateSigner();
                try
                {
                    ml.initSign(ctx, priv.getReference(), new byte[0], 0,
                            MLDSASignatureSpi.MuHandling.INTERNAL.ordinal(), TestUtil.RNDSrc);
                    return ml.signatureLength(ctx, priv.getType(), TestUtil.RNDSrc);
                }
                finally
                {
                    ml.disposeSigner(ctx);
                }
            }
            SLHDSAServiceNI sl = (SLHDSAServiceNI) ni;
            long ctx = sl.allocateSigner();
            try
            {
                sl.initSign(ctx, priv.getReference(), new byte[0], 0,
                        SLHDSASignatureSpi.MessageEncoding.PURE.ordinal(),
                        SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC.ordinal(), TestUtil.RNDSrc);
                return sl.signatureLength(ctx, priv.getType(), TestUtil.RNDSrc);
            }
            finally
            {
                sl.disposeSigner(ctx);
            }
        }
        finally
        {
            // Keeps the pair, and so its native keys, alive until the probe is done.
            Assertions.assertNotNull(kp);
        }
    }

    /** Whether {@code provider} can make the key a row needs. */
    static boolean serves(Provider provider, String iface)
    {
        String alg = KEY_ALG.get(iface);
        return alg == null || provider.getService("KeyPairGenerator", alg) != null;
    }

    @Test
    public void eachNiInstanceOwnsItsFacts() throws Exception
    {
        List<String> table = new ArrayList<String>();
        List<String> problems = new ArrayList<String>();
        int measured = 0;

        for (String iface : INTERFACES)
        {
            if (!serves(firstProvider(), iface) || !serves(secondProvider(), iface))
            {
                // The base provider serves every key here, so only the FIPS side can be missing one.
                Assertions.assertNull(secondProvider().getService("KeyPairGenerator", KEY_ALG.get(iface)),
                        iface + " was skipped as unserved but " + secondProvider().getName() + " serves it");
                table.add(iface + ": not served by " + secondProvider().getName());
                continue;
            }

            Object first = fresh(BASE, iface);
            Object second = fresh(secondClasses(), iface);
            NativeLengthCache<?> a = cacheOf(first);
            NativeLengthCache<?> b = cacheOf(second);
            Assertions.assertNotSame(a, b, iface + ": the two instances share one cache");

            int va = probe(iface, first, firstProvider());
            String afterFirst = a.probes() + "/" + b.probes();
            int vb = probe(iface, second, secondProvider());
            String afterSecond = a.probes() + "/" + b.probes();
            int vb2 = probe(iface, second, secondProvider());
            String afterRepeat = a.probes() + "/" + b.probes();

            String row = iface + ": " + afterFirst + " -> " + afterSecond + " -> " + afterRepeat
                    + " values " + va + "/" + vb + "/" + vb2;
            table.add(row);
            measured++;
            if (!"1/0".equals(afterFirst) || !"1/1".equals(afterSecond) || !"1/1".equals(afterRepeat))
            {
                problems.add(row);
            }
            if (va <= 0 || va != vb || vb != vb2)
            {
                problems.add(row + " (values differ or are not positive)");
            }
        }

        System.out.println("[fact-cache] " + pairing() + " bridge=" + (Loader.isFFI() ? "FFI" : "JNI")
                + "\n  " + String.join("\n  ", table));
        Assertions.assertEquals(INTERFACES.length, table.size(), "one row per interface");
        Assertions.assertTrue(measured > 0, "no interface was measured");
        Assertions.assertTrue(problems.isEmpty(), "caches not bound per instance:\n  " + String.join("\n  ", problems));
    }
}
