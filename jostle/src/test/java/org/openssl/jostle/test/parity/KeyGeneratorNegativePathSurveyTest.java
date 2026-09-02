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

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31 Group B, KeyGenerator: 14 names across 5 SPI classes.
 *
 * <h2>Random output, so the baseline is a SHAPE and an operate-crossing</h2>
 *
 * <p>Every call returns a fresh key, so {@code getEncoded()} cannot be compared
 * across providers - that comparison would report a divergence on every single
 * baseline. {@link Observation#produced} carries the caller-visible shape
 * instead, and {@link Descriptors#generationStable} runs FIRST: a descriptor
 * that is not stable against the provider's own generator cannot be evidence
 * about another's, so an unstable family is reported rather than compared.
 *
 * <h2>Delta: size against spec, and a conflicting size</h2>
 *
 * <p>{@code init(int)}, {@code init(AlgorithmParameterSpec)},
 * {@code init(SecureRandom)} and no-init are four distinct entry states. The
 * fixed-size aliases (AES128/192/256) additionally admit a CONFLICTING size -
 * {@code getInstance("AES128").init(256)} - which has no analogue in the other
 * three Group B surfaces and is where a size check most plausibly goes wrong.
 *
 * <h2>ABSURD_SIZE never calls generateKey</h2>
 *
 * <p>A provider that defers its bound to generation time would turn that cell
 * into an unbounded generation. The cell measures {@code init} only; if init
 * accepts, the row records accepted-at-init and the deferred check is out of
 * scope with the reason stated.
 */
public class KeyGeneratorNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;

    enum Fault
    {
        NEGATIVE_SIZE_INIT,
        ZERO_SIZE_INIT,
        ABSURD_SIZE_INIT,
        MIN_VALUE_SIZE_INIT,
        WRONG_SPEC_TYPE_INIT,
        NULL_SPEC_INIT,
        NULL_SECURE_RANDOM_INIT,
        CONFLICTING_SIZE_ON_FIXED_ALIAS,
        GENERATE_WITHOUT_INIT,
        GENERATE_TWICE
    }

    static final class Cell
    {
        final String name;
        final String spiClass;
        final int validSize;
        /** True for the fixed-size aliases, where a conflicting size is meaningful. */
        final boolean fixedAlias;
        /**
         * False for the KEM generators, which encapsulate to a RECIPIENT and so
         * cannot generate unattended.
         *
         * <p>Measured: {@code generateKey()} with no init raises
         * {@code IllegalStateException: not initialized}, and
         * {@code init(SecureRandom)} raises {@code UnsupportedOperationException}
         * - they require an AlgorithmParameterSpec carrying the peer's public
         * key. So they have no shape baseline, which is a property of the
         * ALGORITHM and not a descriptor instability. Their faults are still
         * surveyed; only the baseline is skipped, with the reason on the row.
         */
        final boolean generatesUnattended;
        /** Transformation the raw key bytes can be round-tripped through, or null. */
        final String crossTransformation;

        Cell(String name, String spiClass, int validSize, boolean fixedAlias)
        {
            this(name, spiClass, validSize, fixedAlias, true);
        }

        Cell(String name, String spiClass, int validSize, boolean fixedAlias, boolean generatesUnattended)
        {
            this(name, spiClass, validSize, fixedAlias, generatesUnattended, null);
        }

        Cell(String name, String spiClass, int validSize, boolean fixedAlias,
             boolean generatesUnattended, String crossTransformation)
        {
            this.name = name;
            this.spiClass = spiClass;
            this.validSize = validSize;
            this.fixedAlias = fixedAlias;
            this.generatesUnattended = generatesUnattended;
            this.crossTransformation = crossTransformation;
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
        c.add(new Cell("AES", "AESKeyGenerator", 256, false, true, "AES/CBC/PKCS5Padding"));
        c.add(new Cell("AES128", "AESKeyGenerator", 128, true, true, "AES/CBC/PKCS5Padding"));
        c.add(new Cell("ChaCha20", "ChaCha20KeyGenerator", 256, false, true, null));
        c.add(new Cell("DESede", "DESedeKeyGenerator", 192, false, true, "DESede/CBC/PKCS5Padding"));
        c.add(new Cell("ML-KEM-512", "MLKEMKeyGenerator", 0, false, false));
        c.add(new Cell("X25519MLKEM768", "MLXKEMKeyGenerator", 0, false, false));
        return c;
    }

    private static Observation baseline(Provider p, Cell cell)
    {
        return Observer.observe(() -> {
            KeyGenerator g = KeyGenerator.getInstance(cell.name, p);
            if (cell.validSize > 0)
            {
                g.init(cell.validSize);
            }
            return Descriptors.of(g.generateKey()).getBytes("UTF-8");
        });
    }

    /** The descriptor, as an Observation. Used once the stability witness has passed. */
    private static Observation shape(Provider p, Cell cell)
    {
        return Observer.observe(() -> {
            KeyGenerator g = KeyGenerator.getInstance(cell.name, p);
            if (cell.validSize > 0)
            {
                g.init(cell.validSize);
            }
            return Descriptors.of(g.generateKey()).getBytes("UTF-8");
        });
    }

    private static Observation applyFault(Provider p, Cell cell, Fault f)
    {
        return Observer.observe(() -> {
            KeyGenerator g = KeyGenerator.getInstance(cell.name, p);
            switch (f)
            {
                case NEGATIVE_SIZE_INIT:
                    g.init(-1);
                    return null;
                case ZERO_SIZE_INIT:
                    g.init(0);
                    return null;
                case ABSURD_SIZE_INIT:
                    // init ONLY - never generateKey. A provider deferring its
                    // bound to generation time would otherwise turn this cell
                    // into an unbounded allocation.
                    g.init(1 << 26);
                    return null;
                case MIN_VALUE_SIZE_INIT:
                    g.init(Integer.MIN_VALUE);
                    return null;
                case WRONG_SPEC_TYPE_INIT:
                    g.init(new IvParameterSpec(new byte[16]));
                    return null;
                case NULL_SPEC_INIT:
                    g.init((java.security.spec.AlgorithmParameterSpec) null);
                    return null;
                case NULL_SECURE_RANDOM_INIT:
                    g.init((SecureRandom) null);
                    return null;
                case CONFLICTING_SIZE_ON_FIXED_ALIAS:
                    // AES128 asked for 256 bits. Only meaningful on an alias
                    // whose name already fixes the size.
                    g.init(256);
                    return Descriptors.of(g.generateKey()).getBytes("UTF-8");
                case GENERATE_WITHOUT_INIT:
                    return Descriptors.of(g.generateKey()).getBytes("UTF-8");
                case GENERATE_TWICE:
                {
                    if (cell.validSize > 0)
                    {
                        g.init(cell.validSize);
                    }
                    g.generateKey();
                    return Descriptors.of(g.generateKey()).getBytes("UTF-8");
                }
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    static boolean applicable(Cell cell, Fault f)
    {
        if (f == Fault.CONFLICTING_SIZE_ON_FIXED_ALIAS)
        {
            return cell.fixedAlias;
        }
        return true;
    }

    @Test
    public void surveyKeyGeneratorNegativePaths()
    {
        SurveyReport report = new SurveyReport("MT-31 KeyGenerator negative-path survey");
        List<Cell> cells = cells();
        List<String> crossingFailures = new ArrayList<String>();
        int namedExceptions = 0;
        int unstable = 0;

        for (Cell cell : cells)
        {
            Provider jdk = JdkComparator.forService("KeyGenerator", cell.name);

            if (!cell.generatesUnattended)
            {
                // A KEM generator encapsulates to a recipient, so there is no
                // unattended key to describe. Not an instability - see the Cell
                // field's note. Faults still run below.
                report.note(String.format("%-26s %-32s %s  jdk=%s", cell.name, "(shape-stability)",
                        "n/a - encapsulates to a recipient, no unattended generation",
                        jdk == null ? "absent" : jdk.getName()));
                namedExceptions++;
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
                continue;
            }

            // The self-witness, BEFORE any cross-provider comparison: generate
            // twice on OUR provider and require the descriptor to hold.
            Descriptors.Stability st = Descriptors.generationStable(() -> {
                KeyGenerator g = KeyGenerator.getInstance(cell.name, jsl);
                if (cell.validSize > 0)
                {
                    g.init(cell.validSize);
                }
                return Descriptors.of(g.generateKey());
            });
            report.note(String.format("%-26s %-32s %s  jdk=%s", cell.name, "(shape-stability)",
                    st, jdk == null ? "absent" : jdk.getName()));
            if (!st.stable)
            {
                report.baselineFailed("        descriptor NOT generation-stable - not compared across providers");
                unstable++;
                continue;
            }

            ParityResult base = ExceptionParity.classify(baseline(jsl, cell), baseline(bc, cell));
            report.note(String.format("%-26s %-32s %s", cell.name, "(baseline-shape)", base.verdict()));

            // The operate-crossing. For a SECRET key a round-trip alone proves
            // nothing about zeros - a constant key round-trips perfectly - so
            // the crossing also requires two generations to differ.
            if (cell.crossTransformation == null)
            {
                report.note(String.format("%-26s %-32s NAMED EXCEPTION: %s", cell.name, "(baseline-operate)",
                        "ChaCha20 has no shared IV-taking Cipher transformation across both providers"
                                + " (BouncyCastle names the key ChaCha7539); distinctness alone is checked"));
                OperateCrossing.Result d = OperateCrossing.distinctness(jsl, cell.name, cell.validSize);
                report.note(String.format("%-26s %-32s distinctness-only: %s", cell.name, "", d));
                if (!d.crossed)
                {
                    crossingFailures.add(cell.name + " (distinctness): " + d.detail);
                }
                namedExceptions++;
            }
            else
            {
                OperateCrossing.Result x = OperateCrossing.symmetric(jsl, bc, cell.name,
                        cell.validSize, cell.crossTransformation);
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
        System.out.println("  descriptor-unstable families: " + unstable);
        // Absolute floor: six cells times ten faults, less the five cells that
        // carry no fixed-size alias.
        report.assertMeasured(55, cells.size(), 0);

        // The operate-crossing is a GATE, not an instrument row.
        Assertions.assertTrue(crossingFailures.isEmpty(),
                "operate-crossing FAILED - a generated secret key could not be used by the other"
                        + " provider, or was not distinct across generations: " + crossingFailures);
        Assertions.assertEquals(3, namedExceptions,
                "expected exactly three families with a named no-crossing reason (ChaCha20 and the"
                        + " two KEM generators); a change here means a family gained or lost a crossing");
    }

    @Test
    public void everyKeyGeneratorSpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"KeyGenerator".equals(sv.getType()))
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
        StringBuilder sb = new StringBuilder("\n=== KeyGenerator SPI-class census ===\n");
        for (Map.Entry<String, List<String>> e : byClass.entrySet())
        {
            named += e.getValue().size();
            if (!covered.contains(e.getKey()))
            {
                uncovered.add(e.getKey());
            }
            sb.append(String.format("  %-28s %2d names  %s%n", e.getKey(), e.getValue().size(),
                    covered.contains(e.getKey()) ? "covered" : "NO CELL"));
        }
        sb.append(String.format("  %-28s %2d names across %d classes%n", "TOTAL", named, byClass.size()));
        System.out.println(sb);
        Assertions.assertTrue(byClass.size() >= 4,
                "census found only " + byClass.size() + " KeyGenerator SPI classes; not reading the provider");
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered KeyGenerator count " + direct);
        Assertions.assertTrue(uncovered.isEmpty(),
                "KeyGenerator SPI classes with no survey cell: " + uncovered);
        Set<String> unknown = new HashSet<String>(covered);
        unknown.removeAll(byClass.keySet());
        Assertions.assertTrue(unknown.isEmpty(),
                "survey cells name SPI classes the provider does not register: " + unknown);
    }
}
