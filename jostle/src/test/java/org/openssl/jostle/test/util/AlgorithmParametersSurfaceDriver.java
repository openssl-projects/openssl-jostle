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

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.util.Arrays;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Drives one registered {@code AlgorithmParameters} name, for both providers'
 * guards.
 *
 * <p>The spec AND its length come from the SPI class: the CBC codec takes a
 * 16-byte IV only and the CCM codec a 7..13-byte nonce, so one shared length
 * would skip whichever codec it did not suit.
 */
public final class AlgorithmParametersSurfaceDriver
{
    private static final String BC = "BC";

    /** Every SPI class sits under this one prefix, so no package list is needed. */
    public static final String PREFIX = "org.openssl.jostle.jcajce.provider.";

    /** Fixed, not random: the two providers share one spec, so a red reproduces. */
    private static final byte[] IV16 = {
            (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55,
            (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB,
            (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF};

    private static final byte[] NONCE12 = {
            (byte) 0x0A, (byte) 0x1B, (byte) 0x2C, (byte) 0x3D, (byte) 0x4E, (byte) 0x5F,
            (byte) 0x60, (byte) 0x71, (byte) 0x82, (byte) 0x93, (byte) 0xA4, (byte) 0xB5};

    /** How to build a valid spec for one SPI class. */
    private interface SpecSource
    {
        AlgorithmParameterSpec get() throws Exception;
    }

    /** One SPI class: how to drive it, and the family name its OIDs pin to. */
    private static final class Row
    {
        private final SpecSource spec;
        private final String family;

        private Row(SpecSource spec, String family)
        {
            this.spec = spec;
            this.family = family;
        }
    }

    /**
     * One table, one fact per SPI class. A miss throws naming the class; there
     * is no default row, because a default would drive a new codec with
     * whatever happened to fit and report success.
     */
    private static final Map<String, Row> TABLE = buildTable();

    private static Map<String, Row> buildTable()
    {
        Map<String, Row> t = new LinkedHashMap<String, Row>();
        t.put("CBCAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get()
            {
                return new IvParameterSpec(IV16);
            }
        }, "AES"));
        t.put("IvAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get()
            {
                return new IvParameterSpec(IV16);
            }
        }, "AES"));
        t.put("GCMAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get()
            {
                return new GCMParameterSpec(128, NONCE12);
            }
        }, "GCM"));
        // A GCMParameterSpec, not an IvParameterSpec: BouncyCastle's CCM codec
        // refuses an IvParameterSpec at every length, so an IV-shaped spec
        // would leave every CCM name with no BC comparison.
        t.put("CCMAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get()
            {
                return new GCMParameterSpec(128, NONCE12);
            }
        }, "CCM"));
        t.put("RSAPSSAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get()
            {
                return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
            }
        }, "RSASSA-PSS"));
        t.put("ECAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get()
            {
                return new ECGenParameterSpec("secp256r1");
            }
        }, "EC"));
        t.put("DSAAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get() throws Exception
            {
                return generatedSpec("DSA");
            }
        }, "DSA"));
        t.put("DHAlgorithmParameters", new Row(new SpecSource()
        {
            public AlgorithmParameterSpec get() throws Exception
            {
                return generatedSpec("DH");
            }
        }, "DH"));
        return t;
    }

    /** The table's key set; the reverse-direction guard reads it. */
    public static final String[] KNOWN_SPI_CLASSES =
            TABLE.keySet().toArray(new String[TABLE.size()]);

    /**
     * Generated through JSL whichever provider is under test: the FIPS module
     * refuses DSA key generation and PKCS#3 DH parameter generation, and one
     * cached spec fed to both keeps this a comparison of codecs.
     */
    private static AlgorithmParameterSpec dsaSpec;
    private static AlgorithmParameterSpec dhSpec;

    private AlgorithmParametersSurfaceDriver()
    {
    }

    public static ProviderSurfaceGuard.ServiceDriver forProvider(final String provider)
    {
        return new ProviderSurfaceGuard.ServiceDriver()
        {
            public void drive(String type, String alg) throws Exception
            {
                if (!"AlgorithmParameters".equals(type))
                {
                    throw new IllegalStateException("no drive defined for " + type + "." + alg
                            + " — teach this driver rather than letting it go unexercised");
                }
                driveOne(provider, alg);
            }
        };
    }

    /** The SPI class a registered name resolves to; the table's key. */
    public static String spiClassOf(String provider, String alg)
    {
        Provider.Service s = Security.getProvider(provider).getService("AlgorithmParameters", alg);
        Assertions.assertNotNull(s, alg + ": discovered but does not resolve");
        String cn = s.getClassName();
        return cn.substring(cn.lastIndexOf('.') + 1);
    }

    /** A valid encoding of {@code alg} through {@code provider}, spec from the table. */
    public static byte[] encodeThrough(String provider, String alg) throws Exception
    {
        return encode(alg, provider, rowFor(provider, alg).spec.get());
    }

    private static Row rowFor(String provider, String alg)
    {
        String spi = spiClassOf(provider, alg);
        Row row = TABLE.get(spi);
        if (row == null)
        {
            throw new IllegalStateException(alg + ": no spec defined for SPI class " + spi
                    + " — add a row rather than letting this name go undriven");
        }
        return row;
    }

    static void driveOne(String provider, String alg) throws Exception
    {
        Row row = rowFor(provider, alg);
        AlgorithmParameterSpec spec = row.spec.get();
        byte[] ours = encode(alg, provider, spec);

        AlgorithmParameters back = AlgorithmParameters.getInstance(alg, provider);
        back.init(ours);
        Assertions.assertTrue(Arrays.areEqual(ours, back.getEncoded()),
                alg + ": our own codec did not round-trip its encoding");

        Provider bc = Security.getProvider(BC);
        Assertions.assertNotNull(bc,
                "BouncyCastle is not registered, so every name would take the no-BC branch and the"
                        + " guard would compare us with ourselves");

        String bcName = bcName(alg);
        if (bc.getService("AlgorithmParameters", bcName) != null)
        {
            byte[] theirs = encode(bcName, BC, spec);
            Assertions.assertTrue(Arrays.areEqual(ours, theirs),
                    alg + ": encoding differs from BouncyCastle's " + bcName + " codec");

            AlgorithmParameters bcBack = AlgorithmParameters.getInstance(bcName, BC);
            bcBack.init(ours);
            Assertions.assertTrue(Arrays.areEqual(ours, bcBack.getEncoded()),
                    alg + ": BouncyCastle re-encoded our bytes differently");
            return;
        }

        // BC does not serve this spelling. Two measures, not one: the family's
        // named codec is compared against BC, and this name is required to
        // equal it. Both are asserted unconditionally — a missing BC family
        // codec would leave only a self-comparison, which is the thing this
        // branch exists to avoid.
        String family = row.family;
        byte[] namedOurs = encode(family, provider, spec);
        Assertions.assertTrue(Arrays.areEqual(ours, namedOurs),
                alg + ": disagrees with our own " + family + " codec");

        String familyBc = bcName(family);
        Assertions.assertNotNull(bc.getService("AlgorithmParameters", familyBc),
                alg + ": BouncyCastle serves neither this name nor " + familyBc + ", so the pin"
                        + " would rest on a self-comparison");
        Assertions.assertTrue(Arrays.areEqual(namedOurs, encode(familyBc, BC, spec)),
                alg + ": the " + family + " codec this name is pinned to disagrees with"
                        + " BouncyCastle");
    }

    private static synchronized AlgorithmParameterSpec generatedSpec(String family)
        throws Exception
    {
        boolean dsa = "DSA".equals(family);
        if (dsa && dsaSpec != null)
        {
            return dsaSpec;
        }
        if (!dsa && dhSpec != null)
        {
            return dhSpec;
        }

        String jsl = org.openssl.jostle.jcajce.provider.JostleProvider.PROVIDER_NAME;
        AlgorithmParameterGenerator g = AlgorithmParameterGenerator.getInstance(family, jsl);
        g.init(dsa ? 2048 : 1024);
        AlgorithmParameters p = g.generateParameters();
        AlgorithmParameterSpec spec = dsa
                ? p.getParameterSpec(java.security.spec.DSAParameterSpec.class)
                : p.getParameterSpec(javax.crypto.spec.DHParameterSpec.class);

        if (dsa)
        {
            dsaSpec = spec;
        }
        else
        {
            dhSpec = spec;
        }
        return spec;
    }

    /** BouncyCastle's spelling, applied at the BC call site only. */
    private static String bcName(String alg)
    {
        return "RSASSA-PSS".equals(alg.toUpperCase(Locale.ROOT)) ? "PSS" : alg;
    }

    private static byte[] encode(String alg, String provider, AlgorithmParameterSpec spec)
        throws Exception
    {
        AlgorithmParameters p = AlgorithmParameters.getInstance(alg, provider);
        p.init(spec);
        return p.getEncoded();
    }
}
