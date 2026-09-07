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
 *   <li><b>The floor, the shape and the ceiling are now OpenSSL's, not ours.</b>
 *       This table used to carry a WE_ARE_ODD row at 512: we refused it and both
 *       references accepted. Arc C removed the 1024 floor, the DH
 *       multiple-of-64 rule and the DSA {@code {1024, 2048, 3072}} set, none of
 *       which OpenSSL imposes - measured, 511 is refused and 512, 513, 767,
 *       1000, 1023, 1025 and 2047 all generate.
 *
 *       <p>What remains pinned is the boundary itself, 511 refused and 512
 *       accepted by all three, plus the sizes where BouncyCastle's DSA refuses
 *       by its OWN documented shape rule (multiple of 64 below 1024, multiple
 *       of 1024 above, ceiling 3072). Those are BC's rules rather than defects,
 *       and pinning them stops a parity sweep "fixing" our acceptance to match.
 *
 *       <p>The 1024 DH floor was a Logjam-grade security judgement, and removing
 *       it is NOT a claim that 512-bit DH is safe - it is not. Choosing a
 *       modulus size is the caller's decision, and this provider had been making
 *       it for them.</li>
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
        /** 511: one below OpenSSL's floor. All three refuse. */
        INIT_BELOW_FLOOR,
        /** 512: OpenSSL's floor exactly. All three accept. */
        INIT_AT_FLOOR,
        /** 513: legal for OpenSSL, refused by BouncyCastle's DSA shape rule. */
        INIT_UNALIGNED,
        /** 1000: also unaligned, and above 512, to show it is not a 513 quirk. */
        INIT_UNALIGNED_LARGE,
        /** 4096: legal for OpenSSL, above BouncyCastle's 3072 DSA ceiling. */
        INIT_ABOVE_BC_CEILING,
        /** 10001: one above OPENSSL_{DSA,DH}_MAX_MODULUS_BITS. We refuse. */
        INIT_ABOVE_CEILING,
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
                    g.init(511);
                    return null;
                case INIT_AT_FLOOR:
                    g.init(512);
                    return null;
                case INIT_UNALIGNED:
                    g.init(513);
                    return null;
                case INIT_UNALIGNED_LARGE:
                    g.init(1000);
                    return null;
                case INIT_ABOVE_BC_CEILING:
                    g.init(4096);
                    return null;
                case INIT_ABOVE_CEILING:
                    g.init(10001);
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
        // Absolute floor: two names times fourteen faults.
        report.assertMeasured(28, names.size(), 0);
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

        // 1. THE FLOOR MOVED. 512 was our refusal and both references' accept -
        //    the WE_ARE_ODD row this table used to carry. Arc C dropped the
        //    floor to OpenSSL's own, so all three now accept 512 and all three
        //    refuse 511. Both halves are asserted: a floor that crept back up
        //    fails the 512 row, and one that vanished fails the 511 row.
        for (String name : names())
        {
            refuses(jsl, name, Fault.INIT_BELOW_FLOOR, java.security.InvalidParameterException.class);
            accepts(jsl, name, Fault.INIT_AT_FLOOR);
            accepts(bc, name, Fault.INIT_AT_FLOOR);
        }
        accepts(dhJdk, "DH", Fault.INIT_AT_FLOOR);
        accepts(dsaJdk, "DSA", Fault.INIT_AT_FLOOR);

        //    The DSA discrete set {1024, 2048, 3072} and the DH multiple-of-64
        //    rule went with it: OpenSSL imposes neither (measured - 513, 767,
        //    1000, 1023, 1025 and 2047 all generate), so we accept them and
        //    BouncyCastle's DSA refuses by ITS OWN documented shape rule
        //    ("multiple of 64 below 1024", "multiple of 1024 above"). That is
        //    BC's rule, not a defect, and it is pinned so a parity sweep cannot
        //    "fix" our acceptance to match it.
        for (String name : names())
        {
            accepts(jsl, name, Fault.INIT_UNALIGNED);
            accepts(jsl, name, Fault.INIT_UNALIGNED_LARGE);
            accepts(jsl, name, Fault.INIT_ABOVE_BC_CEILING);
        }
        refuses(bc, "DSA", Fault.INIT_UNALIGNED, java.security.InvalidParameterException.class);
        refuses(bc, "DSA", Fault.INIT_UNALIGNED_LARGE, java.security.InvalidParameterException.class);
        refuses(bc, "DSA", Fault.INIT_ABOVE_BC_CEILING, java.security.InvalidParameterException.class);

        //    The CEILING is inherited too, and is the one bound OpenSSL does not
        //    enforce at paramgen: OPENSSL_DSA_MAX_MODULUS_BITS
        //    (openssl include/openssl/dsa.h:61) is checked at parameter
        //    validation (crypto/dsa/dsa_check.c:30) and at sign
        //    (crypto/dsa/dsa_ossl.c:378), and OPENSSL_DH_MAX_MODULUS_BITS
        //    (include/openssl/dh.h:99) is checked up front. So generating above
        //    10000 is unbounded cost for a parameter set OpenSSL will not
        //    validate or use - which is why WE refuse it at init. 10000 is
        //    OpenSSL's number, not a jostle policy number.
        for (String name : names())
        {
            refuses(jsl, name, Fault.INIT_ABOVE_CEILING, java.security.InvalidParameterException.class);
        }

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
