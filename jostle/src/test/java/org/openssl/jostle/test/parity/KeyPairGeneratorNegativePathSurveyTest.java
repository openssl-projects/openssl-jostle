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

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31 Group B, KeyPairGenerator: 34 names across 10 SPI classes.
 *
 * <h2>Delta: one fault, TWO specified exception types</h2>
 *
 * <p>JCA mandates different types for the two init overloads -
 * {@code initialize(int)} raises {@code InvalidParameterException} (unchecked),
 * {@code initialize(AlgorithmParameterSpec)} raises
 * {@code InvalidAlgorithmParameterException} (checked). So a bad key size has
 * two correct answers depending on how it was supplied.
 *
 * <p>Every size fault is therefore pinned BY OVERLOAD and named accordingly. A
 * catalogue that ran one size fault through whichever overload was convenient
 * would report a CHECKED_DIVERGENCE against a difference the specification
 * requires.
 *
 * <h2>Size faults call initialize() ONLY</h2>
 *
 * <p>Never {@code generateKeyPair}. A provider that defers its bound to
 * generation time would turn an absurd size into a multi-minute or unbounded
 * RSA generation. Where init accepts, the row records accepted-at-init and the
 * deferred check is out of scope, with the reason stated here rather than
 * silently.
 *
 * <h2>Looking for the MT-46 shape from the other side</h2>
 *
 * <p>MT-46 found our RSA KeyFactory importing a 12-bit modulus while our
 * KeyPairGenerator pins a 1024-bit floor for generation. {@code BELOW_FLOOR_SIZE_INT}
 * probes the generator half of that pair directly: 512 bits, which is above the
 * JDK's documented floor and below ours.
 */
public class KeyPairGeneratorNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;

    enum Fault
    {
        NEGATIVE_SIZE_INT,
        ZERO_SIZE_INT,
        ABSURD_SIZE_INT,
        MIN_VALUE_SIZE_INT,
        BELOW_FLOOR_SIZE_INT,
        NULL_SPEC_INITIALIZE,
        WRONG_SPEC_TYPE_INITIALIZE,
        NULL_SECURE_RANDOM_WITH_INT,
        NULL_SECURE_RANDOM_WITH_SPEC,
        GENERATE_WITHOUT_INIT,
        GENERATE_TWICE
    }

    static final class Cell
    {
        final String name;
        final String spiClass;
        /** A size the int overload accepts, or 0 when the family takes no size. */
        final int validSize;
        /** True where a below-floor size is meaningful - RSA and the FFC families. */
        final boolean sized;
        /** How this family's keys can be operate-crossed, and through what name. */
        final OperateCrossing.Op op;
        final String opAlgorithm;
        final String keyFactory;
        /** Why no crossing exists, for the families where op is NONE. */
        final String noCrossReason;

        Cell(String name, String spiClass, int validSize, boolean sized,
             OperateCrossing.Op op, String opAlgorithm, String keyFactory, String noCrossReason)
        {
            this.name = name;
            this.spiClass = spiClass;
            this.validSize = validSize;
            this.sized = sized;
            this.op = op;
            this.opAlgorithm = opAlgorithm;
            this.keyFactory = keyFactory;
            this.noCrossReason = noCrossReason;
        }
    }

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
    }

    static List<Cell> cells()
    {
        List<Cell> c = new ArrayList<Cell>();
        c.add(new Cell("RSA", "RSAKeyPairGenerator", 2048, true,
                OperateCrossing.Op.SIGNATURE, "SHA256withRSA", "RSA", null));
        c.add(new Cell("DSA", "DSAKeyPairGenerator", 2048, true,
                OperateCrossing.Op.SIGNATURE, "SHA256withDSA", "DSA", null));
        c.add(new Cell("DH", "DHKeyPairGenerator", 2048, true,
                OperateCrossing.Op.KEY_AGREEMENT, "DH", "DH", null));
        c.add(new Cell("EC", "ECKeyPairGenerator", 256, false,
                OperateCrossing.Op.SIGNATURE, "SHA256withECDSA", "EC", null));
        c.add(new Cell("Ed25519", "EdDSAKeyPairGenerator", 0, false,
                OperateCrossing.Op.SIGNATURE, "Ed25519", "Ed25519", null));
        c.add(new Cell("X25519", "XECKeyPairGenerator", 0, false,
                OperateCrossing.Op.KEY_AGREEMENT, "X25519", "X25519", null));
        c.add(new Cell("ML-DSA-44", "MLDSAKeyPairGeneratorImpl", 0, false,
                OperateCrossing.Op.SIGNATURE, "ML-DSA-44", "ML-DSA", null));
        c.add(new Cell("ML-KEM-512", "MLKEMKeyPairGenerator", 0, false,
                OperateCrossing.Op.NONE, null, "ML-KEM",
                "a KEM: no Signature or KeyAgreement surface takes these keys, and the"
                        + " encapsulation path is a KeyGenerator/Cipher contract surveyed elsewhere"));
        c.add(new Cell("SLH-DSA-SHA2-128F", "SLHDSAKeyPairGenerator", 0, false,
                OperateCrossing.Op.SIGNATURE, "SLH-DSA-SHA2-128F", "SLH-DSA", null));
        c.add(new Cell("X25519MLKEM768", "MLXKEMKeyPairGenerator", 0, false,
                OperateCrossing.Op.NONE, null, null,
                "the TLS hybrid KEMs have NO encoding at all, so no key material can cross"));
        return c;
    }

    private static String describe(Provider p, Cell cell) throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance(cell.name, p);
        if (cell.validSize > 0)
        {
            g.initialize(cell.validSize);
        }
        return Descriptors.of(g.generateKeyPair());
    }

    private static Observation baseline(Provider p, Cell cell)
    {
        return Observer.observe(() -> describe(p, cell).getBytes("UTF-8"));
    }

    private static Observation applyFault(Provider p, Cell cell, Fault f)
    {
        return Observer.observe(() -> {
            KeyPairGenerator g = KeyPairGenerator.getInstance(cell.name, p);
            switch (f)
            {
                // ---- the int overload: JCA mandates InvalidParameterException
                case NEGATIVE_SIZE_INT:
                    g.initialize(-1);
                    return null;
                case ZERO_SIZE_INT:
                    g.initialize(0);
                    return null;
                case ABSURD_SIZE_INT:
                    // initialize ONLY - an RSA generation at this size would
                    // not return within the life of the test run.
                    g.initialize(1 << 26);
                    return null;
                case MIN_VALUE_SIZE_INT:
                    g.initialize(Integer.MIN_VALUE);
                    return null;
                case BELOW_FLOOR_SIZE_INT:
                    // 512: above the JDK's documented RSA floor, below ours.
                    g.initialize(512);
                    return null;
                case NULL_SECURE_RANDOM_WITH_INT:
                    g.initialize(cell.validSize > 0 ? cell.validSize : 256, null);
                    return null;

                // ---- the spec overload: JCA mandates InvalidAlgorithmParameterException
                case NULL_SPEC_INITIALIZE:
                    g.initialize((AlgorithmParameterSpec) null);
                    return null;
                case WRONG_SPEC_TYPE_INITIALIZE:
                    g.initialize(new IvParameterSpec(new byte[16]));
                    return null;
                case NULL_SECURE_RANDOM_WITH_SPEC:
                    g.initialize(new IvParameterSpec(new byte[16]), (SecureRandom) null);
                    return null;

                // ---- generation state
                case GENERATE_WITHOUT_INIT:
                    return Descriptors.of(g.generateKeyPair()).getBytes("UTF-8");
                case GENERATE_TWICE:
                    if (cell.validSize > 0)
                    {
                        g.initialize(cell.validSize);
                    }
                    g.generateKeyPair();
                    return Descriptors.of(g.generateKeyPair()).getBytes("UTF-8");
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    static boolean applicable(Cell cell, Fault f)
    {
        if (f == Fault.BELOW_FLOOR_SIZE_INT)
        {
            // Only meaningful where a size means bits of a modulus or prime.
            return cell.sized;
        }
        return true;
    }

    @Test
    public void surveyKeyPairGeneratorNegativePaths()
    {
        SurveyReport report = new SurveyReport("MT-31 KeyPairGenerator negative-path survey");
        List<Cell> cells = cells();
        List<String> crossingFailures = new ArrayList<String>();
        int namedExceptions = 0;

        for (Cell cell : cells)
        {
            Provider jdk = JdkComparator.forService("KeyPairGenerator", cell.name);

            // Self-witness first: two generations on OUR provider must describe
            // the same shape. This is where the DER wobble the bucket exists for
            // would show up, so a family failing here is reported not compared.
            Descriptors.Stability st = Descriptors.generationStable(() -> describe(jsl, cell));
            report.note(String.format("%-26s %-32s %s  jdk=%s", cell.name, "(shape-stability)",
                    st, jdk == null ? "absent" : jdk.getName()));
            if (!st.stable)
            {
                report.baselineFailed("        descriptor NOT generation-stable - not compared across providers");
                continue;
            }

            ParityResult base = ExceptionParity.classify(baseline(jsl, cell), baseline(bc, cell));
            report.note(String.format("%-26s %-32s %s", cell.name, "(baseline-shape)", base.verdict()));

            // The operate-crossing: the check a shape descriptor CANNOT make.
            // A correctly-labelled, correctly-sized key full of zeros passes
            // every shape comparison and fails here.
            if (cell.op == OperateCrossing.Op.NONE)
            {
                report.note(String.format("%-26s %-32s NAMED EXCEPTION: %s",
                        cell.name, "(baseline-operate)", cell.noCrossReason));
                namedExceptions++;
            }
            else
            {
                OperateCrossing.Result x = OperateCrossing.asymmetric(jsl, bc, cell.op,
                        cell.name, cell.keyFactory, cell.opAlgorithm, cell.validSize);
                report.note(String.format("%-26s %-32s %s", cell.name, "(baseline-operate)", x));
                if (!x.crossed)
                {
                    crossingFailures.add(cell.name + ": " + x.detail);
                }
            }

            for (Fault f : Fault.values())
            {
                if (!applicable(cell, f))
                {
                    continue;
                }
                report.cell(cell.name, f.name(), ThreeWay.classify(
                        applyFault(jsl, cell, f), applyFault(bc, cell, f),
                        jdk == null ? Observation.absent() : applyFault(jdk, cell, f)));
            }
        }
        // Absolute floor: ten cells times ten shared faults, plus three sized.
        report.assertMeasured(100, cells.size(), 1);

        // The operate-crossing is a GATE, not an instrument row: a family whose
        // key cannot do its own job is a defect, not a divergence pending a
        // ruling. Exactly two named exceptions are expected; a third means a
        // family lost its crossing without anyone saying so.
        Assertions.assertTrue(crossingFailures.isEmpty(),
                "operate-crossing FAILED - a generated key could not be used by the other provider: "
                        + crossingFailures);
        Assertions.assertEquals(2, namedExceptions,
                "expected exactly two families with a named no-crossing reason (ML-KEM-512 and"
                        + " X25519MLKEM768); a change here means a family gained or lost a crossing");
    }

    @Test
    public void everyKeyPairGeneratorSpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"KeyPairGenerator".equals(sv.getType()))
            {
                continue;
            }
            direct++;
            String cn = sv.getClassName();
            String simple = cn.substring(cn.lastIndexOf('.') + 1);
            List<String> l = byClass.get(simple);
            if (l == null)
            {
                l = new ArrayList<String>();
                byClass.put(simple, l);
            }
            l.add(sv.getAlgorithm());
        }
        Set<String> covered = new HashSet<String>();
        for (Cell c : cells())
        {
            covered.add(c.spiClass);
        }
        int named = 0;
        List<String> uncovered = new ArrayList<String>();
        StringBuilder sb = new StringBuilder("\n=== KeyPairGenerator SPI-class census ===\n");
        for (Map.Entry<String, List<String>> e : byClass.entrySet())
        {
            named += e.getValue().size();
            if (!covered.contains(e.getKey()))
            {
                uncovered.add(e.getKey());
            }
            sb.append(String.format("  %-30s %2d names  %s%n", e.getKey(), e.getValue().size(),
                    covered.contains(e.getKey()) ? "covered" : "NO CELL"));
        }
        sb.append(String.format("  %-30s %2d names across %d classes%n", "TOTAL", named, byClass.size()));
        System.out.println(sb);
        Assertions.assertTrue(byClass.size() >= 8,
                "census found only " + byClass.size() + " KeyPairGenerator SPI classes; not reading the provider");
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered KeyPairGenerator count " + direct);
        Assertions.assertTrue(uncovered.isEmpty(),
                "KeyPairGenerator SPI classes with no survey cell: " + uncovered);
        Set<String> unknown = new HashSet<String>(covered);
        unknown.removeAll(byClass.keySet());
        Assertions.assertTrue(unknown.isEmpty(),
                "survey cells name SPI classes the provider does not register: " + unknown);
    }
}
