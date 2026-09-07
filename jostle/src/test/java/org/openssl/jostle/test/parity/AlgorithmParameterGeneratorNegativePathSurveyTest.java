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
import java.security.AlgorithmParameterGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

/**
 * MT-31 Group C, arc 3a: our exception type against BouncyCastle's and the
 * JDK's, for both registered {@code AlgorithmParameterGenerator} names and every
 * negative path.
 *
 * <p>Two names, two SPI classes ({@code DHAlgorithmParameterGenerator},
 * {@code DSAAlgorithmParameterGenerator}), and both references serve both names -
 * so every cell here is ATTRIBUTABLE, which is unusual and is why the surface is
 * worth surveying despite its size.
 *
 * <h2>Two divergences this table pins. Neither is fixed here.</h2>
 *
 * <ol>
 *   <li><b>BouncyCastle accepts every illegal DH parameter size</b> -
 *       {@code init(-1)}, {@code init(0)}, {@code init(MIN_VALUE)} and
 *       {@code init(1 << 26)} are all ACCEPTED by its DH generator, while we and
 *       the JDK raise {@code InvalidParameterException}. BC_IS_ODD, four times.
 *       This is MT-49's class (BouncyCastle accepts every illegal
 *       {@code KeyGenerator} size) on a new surface, and it is DH-specific
 *       WITHIN BouncyCastle: its DSA generator refuses the same values. A row
 *       for the upstream bundle, not a defect of ours.</li>
 *   <li><b>We refuse a 512-bit size where BOTH references accept</b>, on DH and
 *       DSA alike. WE_ARE_ODD, twice. <b>The two floors differ in KIND</b>, which
 *       matters if anyone revisits them:
 *       <ul>
 *         <li>DSA's {@code {1024, 2048, 3072}} is the FIPS 186-4 &sect;4.2 (L, N)
 *             set - a standards set, not a local policy choice.</li>
 *         <li>DH's 1024 floor is a jostle policy choice, and its own comment
 *             says so: "Security floor - DH below 1024 bits (Logjam-grade export
 *             DH) is refused outright".</li>
 *       </ul>
 *       MT-66 ruled that jostle's RSA key-size support is what OpenSSL supports,
 *       with no jostle-side policy floor. Whether that principle reaches DH and
 *       DSA parameter generation is Megan's call. This table PINS current
 *       behaviour so a later sweep cannot move it silently, and a change of
 *       policy is expected to change this test deliberately.</li>
 * </ol>
 *
 * <h2>Two cells are deliberately NOT faults</h2>
 *
 * <p>{@code INIT_NULL_RANDOM} and {@code GENERATE_NO_INIT} are legal calls that
 * all three providers accept. They are recorded so that a future edit which
 * starts REFUSING them is caught: a fault survey measures bad input and is
 * structurally blind to an over-refusal of good input, so the positive cells
 * have to be carried explicitly.
 */
public class AlgorithmParameterGeneratorNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;

    public static final String TYPE = "AlgorithmParameterGenerator";

    public enum Fault
    {
        INIT_NEGATIVE,
        INIT_ZERO,
        INIT_MIN_VALUE,
        INIT_ABSURD,
        INIT_BELOW_FLOOR,
        INIT_NULL_SPEC,
        INIT_FOREIGN_SPEC,
        /** Not a fault: a null SecureRandom means "use the default". */
        INIT_NULL_RANDOM,
        /** Not a fault: generating with no init is legal and uses a default. */
        GENERATE_NO_INIT
    }

    /** Empty by MEASUREMENT - both references serve both names. */
    private static final TreeSet<String> PINNED = new TreeSet<String>();
    private static final TreeSet<String> BLOCKED = new TreeSet<String>();

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

    static List<String> names()
    {
        List<String> l = new ArrayList<String>();
        for (Provider.Service sv : jsl.getServices())
        {
            if (TYPE.equals(sv.getType()) && sv.getAlgorithm().indexOf('.') < 0)
            {
                // OID aliases resolve to the same SPI; the primaries are the axis.
                l.add(sv.getAlgorithm());
            }
        }
        Collections.sort(l);
        return l;
    }

    public static Observation applyFault(Provider p, String name, Fault f)
    {
        return Observer.observe(() -> {
            AlgorithmParameterGenerator g = AlgorithmParameterGenerator.getInstance(name, p);
            switch (f)
            {
                case INIT_NEGATIVE:
                    g.init(-1);
                    return null;
                case INIT_ZERO:
                    g.init(0);
                    return null;
                case INIT_MIN_VALUE:
                    g.init(Integer.MIN_VALUE);
                    return null;
                case INIT_ABSURD:
                    // Large enough to be plainly illegal, small enough that an
                    // unbounded provider does not search for primes for minutes.
                    g.init(1 << 26);
                    return null;
                case INIT_BELOW_FLOOR:
                    g.init(512);
                    return null;
                case INIT_NULL_SPEC:
                    g.init((AlgorithmParameterSpec) null);
                    return null;
                case INIT_FOREIGN_SPEC:
                    g.init(new IvParameterSpec(new byte[16]));
                    return null;
                case INIT_NULL_RANDOM:
                    g.init(1024, null);
                    return null;
                case GENERATE_NO_INIT:
                    return g.generateParameters().getEncoded();
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    @Test
    public void surveyAlgorithmParameterGeneratorNegativePaths()
    {
        SurveyReport report = new SurveyReport(
                "MT-31 Group C AlgorithmParameterGenerator negative-path survey");
        List<String> names = names();

        for (String name : names)
        {
            Provider jdk = JdkComparator.forService(TYPE, name);
            report.note(String.format("%-8s (comparability)  bc=%s  jdk=%s", name,
                    bc.getService(TYPE, name) == null ? "absent" : "present",
                    jdk == null ? "absent" : jdk.getName()));

            for (Fault f : Fault.values())
            {
                report.cell(name, f.name(), ThreeWay.classify(
                        applyFault(jsl, name, f),
                        bc.getService(TYPE, name) == null
                                ? Observation.absent() : applyFault(bc, name, f),
                        jdk == null ? Observation.absent() : applyFault(jdk, name, f)));
            }
        }
        // Absolute floor: two names times nine faults.
        report.assertMeasured(18, names.size(), 0);
    }

    /**
     * The divergences this surface carries, ASSERTED - because the survey does
     * not.
     *
     * <p>{@link #surveyAlgorithmParameterGeneratorNegativePaths()} records cells
     * and asserts only the measured floor, so it is a MEASUREMENT: if we stopped
     * refusing 512, or started refusing a null {@code SecureRandom}, it would
     * stay green and only the printed report would change. The class javadoc
     * says the positive cells are carried "so that a future edit which starts
     * REFUSING them is caught" - which is only true with an assertion, and this
     * is that assertion.
     *
     * <p><b>The references' behaviour is asserted deliberately.</b> A bcprov or
     * JDK bump that moves one FAILS this test loudly; the reason a divergence
     * was accepted may have moved with it.
     */
    @Test
    public void pinnedDivergences()
    {
        Provider dhJdk = JdkComparator.forService(TYPE, "DH");
        Provider dsaJdk = JdkComparator.forService(TYPE, "DSA");
        Assertions.assertNotNull(dhJdk, "no JDK DH parameter generator; the JDK half cannot run");
        Assertions.assertNotNull(dsaJdk, "no JDK DSA parameter generator; the JDK half cannot run");

        // 1. A 512-bit size: we refuse, both references accept. WE are the odd
        //    provider, on both names, and the two floors differ in KIND -
        //    DSA's {1024, 2048, 3072} is the FIPS 186-4 4.2 (L, N) set, while
        //    DH's 1024 is a jostle policy choice against Logjam-grade export DH.
        //    MT-66 ruled there is no jostle-side RSA floor; whether that reaches
        //    here is Megan's call, so this pins current behaviour rather than
        //    endorsing it.
        for (String name : names())
        {
            refuses(jsl, name, Fault.INIT_BELOW_FLOOR, java.security.InvalidParameterException.class);
        }
        accepts(bc, "DH", Fault.INIT_BELOW_FLOOR);
        accepts(bc, "DSA", Fault.INIT_BELOW_FLOOR);
        accepts(dhJdk, "DH", Fault.INIT_BELOW_FLOOR);
        accepts(dsaJdk, "DSA", Fault.INIT_BELOW_FLOOR);

        // 2. BouncyCastle accepts every illegal DH size while REFUSING the same
        //    values on DSA. Both halves are asserted, because the DH-specific
        //    half is what makes this a BouncyCastle finding rather than a
        //    difference of policy: the same library answers the same question
        //    two ways.
        for (Fault f : new Fault[]{Fault.INIT_NEGATIVE, Fault.INIT_ZERO,
                Fault.INIT_MIN_VALUE, Fault.INIT_ABSURD})
        {
            refuses(jsl, "DH", f, java.security.InvalidParameterException.class);
            refuses(jsl, "DSA", f, java.security.InvalidParameterException.class);
            accepts(bc, "DH", f);
            refuses(bc, "DSA", f, java.security.InvalidParameterException.class);
            refuses(dhJdk, "DH", f, java.security.InvalidParameterException.class);
            refuses(dsaJdk, "DSA", f, java.security.InvalidParameterException.class);
        }

        // 3. The two positive cells. A fault survey is structurally blind to an
        //    over-refusal of GOOD input, so the only thing that can catch one is
        //    an assertion that these still work.
        for (String name : names())
        {
            accepts(jsl, name, Fault.INIT_NULL_RANDOM);
            accepts(jsl, name, Fault.GENERATE_NO_INIT);
        }
    }

    /** Assert a provider refuses this cell with EXACTLY this class. */
    private static void refuses(Provider p, String name, Fault f, Class<?> expected)
    {
        Observation o = applyFault(p, name, f);
        Assertions.assertTrue(o.isThrow(),
                p.getName() + " " + name + " " + f + ": expected " + expected.getName()
                        + " but the call was ACCEPTED");
        Assertions.assertEquals(expected, o.thrown().getClass(),
                p.getName() + " " + name + " " + f + ": wrong refusal type"
                        + " (message was: " + o.message() + ")");
    }

    /** Assert a provider ACCEPTS this cell - the other half of a divergence. */
    private static void accepts(Provider p, String name, Fault f)
    {
        Observation o = applyFault(p, name, f);
        Assertions.assertFalse(o.isAbsent(), p.getName() + " does not serve " + name);
        Assertions.assertFalse(o.isThrow(),
                p.getName() + " " + name + " " + f + ": expected acceptance but it refused with "
                        + (o.isThrow() ? o.thrown().getClass().getName() + " / " + o.message() : ""));
    }

    /**
     * Tri-state accounting over the LIVE primaries. CELL is derived rather than
     * listed, so the guard cannot be satisfied by editing a list to match.
     */
    @Test
    public void nameAccountingIsComplete()
    {
        TreeSet<String> live = new TreeSet<String>(names());
        TreeSet<String> cell = new TreeSet<String>(live);
        cell.removeAll(PINNED);
        cell.removeAll(BLOCKED);

        for (String n : PINNED)
        {
            Assertions.assertTrue(live.contains(n), "PINNED names an unregistered generator: " + n);
        }
        // A PINNED entry must be JUSTIFIED, not merely listed. Without this, a
        // name MOVED from CELL to PINNED still satisfies the tally and the
        // guard passes while the name is no longer measured against anything -
        // the exclusion-list vacuity trap. PINNED means "no reference serves
        // it", so that is what is re-derived here, every run.
        for (String n : PINNED)
        {
            Assertions.assertNull(bc.getService(TYPE, n),
                    "PINNED holds " + n + ", but BouncyCastle serves it - it is a CELL,"
                            + " and pinning it silently drops it from the comparison");
            Assertions.assertNull(JdkComparator.forService(TYPE, n),
                    "PINNED holds " + n + ", but the JDK serves it - it is a CELL,"
                            + " and pinning it silently drops it from the comparison");
        }
        for (String n : BLOCKED)
        {
            Assertions.assertTrue(live.contains(n), "BLOCKED names an unregistered generator: " + n);
        }
        TreeSet<String> both = new TreeSet<String>(PINNED);
        both.retainAll(BLOCKED);
        Assertions.assertTrue(both.isEmpty(), "PINNED and BLOCKED overlap: " + both);

        Assertions.assertEquals(live.size(), cell.size() + PINNED.size() + BLOCKED.size(),
                "tri-state tally does not equal the live count; live=" + live
                        + " cell=" + cell + " pinned=" + PINNED + " blocked=" + BLOCKED);
        Assertions.assertEquals(new TreeSet<String>(java.util.Arrays.asList("DH", "DSA")), live,
                "the registered AlgorithmParameterGenerator primaries changed");
        for (String n : cell)
        {
            Assertions.assertNotNull(bc.getService(TYPE, n),
                    "no reference serves " + n + ", so it cannot be a CELL - move it to PINNED");
        }
    }
}
