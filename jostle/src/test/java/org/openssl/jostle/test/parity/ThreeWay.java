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

/**
 * One cell measured against BouncyCastle AND the JDK, with the ATTRIBUTION that
 * two comparators make possible and one does not.
 *
 * <h2>Why this exists</h2>
 *
 * <p>A two-provider survey renders "BouncyCastle is wrong" and "we are wrong"
 * identically. The MessageDigest surface contained one of each and only a third
 * reference separated them: BouncyCastle alone accepted a negative length,
 * while we alone raised {@code IllegalArgumentException} for a negative offset
 * where BouncyCastle and the JDK agreed. From the two-provider table those rows
 * look like the same finding, and the natural reading - "BouncyCastle differs,
 * we are fine" - is wrong for half of them.
 *
 * <h2>The three populations, reported separately</h2>
 *
 * <p>The JDK serves only 37 of Group B's 125 names and BouncyCastle 82, so most
 * cells cannot be attributed and some cannot be compared at all. Pretending
 * otherwise would be the more comfortable report and the less true one:
 *
 * <ul>
 *   <li>{@link Population#ATTRIBUTABLE} - three providers answered. Two against
 *       one names the odd provider; three-way disagreement says the contract is
 *       underspecified, which is itself the finding.</li>
 *   <li>{@link Population#UNATTRIBUTED} - two answered. A divergence is real but
 *       nothing here says whose.</li>
 *   <li>{@link Population#UNCOMPARED} - only we answered. Recorded as a drift
 *       baseline, and explicitly NOT counted as agreement coverage.</li>
 * </ul>
 */
public final class ThreeWay
{
    public enum Population
    {
        ATTRIBUTABLE,
        UNATTRIBUTED,
        UNCOMPARED
    }

    /** Who is the odd one out, when that question has an answer. */
    public enum Attribution
    {
        /** All three agree. */
        ALL_AGREE,
        /** BouncyCastle and the JDK agree; we differ. */
        WE_ARE_ODD,
        /** We and the JDK agree; BouncyCastle differs. */
        BC_IS_ODD,
        /** We and BouncyCastle agree; the JDK differs. */
        JDK_IS_ODD,
        /** All three differ - the contract is underspecified. */
        ALL_DIFFER,
        /** Not enough comparators to say. */
        NOT_ATTRIBUTABLE
    }

    private final Attribution decisionAttribution;
    private final ParityResult vsBc;
    private final ParityResult vsJdk;
    private final Population population;
    private final Attribution attribution;
    private final String ourType;
    private final String bcType;
    private final String jdkType;

    private ThreeWay(ParityResult vsBc, ParityResult vsJdk, Population population,
                     Attribution attribution, Attribution decisionAttribution,
                     String ourType, String bcType, String jdkType)
    {
        this.decisionAttribution = decisionAttribution;
        this.vsBc = vsBc;
        this.vsJdk = vsJdk;
        this.population = population;
        this.attribution = attribution;
        this.ourType = ourType;
        this.bcType = bcType;
        this.jdkType = jdkType;
    }

    /**
     * Classify one cell. Any of {@code bc} or {@code jdk} may be
     * {@link Observation#absent()}, which is how a provider that does not serve
     * the name is recorded - never as a refusal.
     */
    public static ThreeWay classify(Observation ours, Observation bc, Observation jdk)
    {
        if (ours == null || bc == null || jdk == null)
        {
            throw new IllegalArgumentException("three observations are required; use absent() for a provider that does not serve the name");
        }
        boolean hasBc = !bc.isAbsent();
        boolean hasJdk = !jdk.isAbsent();
        ParityResult rb = hasBc ? ExceptionParity.classify(ours, bc) : null;
        ParityResult rj = hasJdk ? ExceptionParity.classify(ours, jdk) : null;

        Population pop = hasBc && hasJdk ? Population.ATTRIBUTABLE
                : (hasBc || hasJdk ? Population.UNATTRIBUTED : Population.UNCOMPARED);

        Attribution att = Attribution.NOT_ATTRIBUTABLE;
        Attribution dec = Attribution.NOT_ATTRIBUTABLE;
        if (pop == Population.ATTRIBUTABLE)
        {
            // The third comparison the survey never runs directly: BouncyCastle
            // against the JDK. Without it "we differ from both" cannot be told
            // apart from "everyone differs".
            att = odd(!isDifference(rb), !isDifference(rj),
                    !isDifference(ExceptionParity.classify(bc, jdk)));
            boolean o = refused(ours);
            boolean b = refused(bc);
            boolean j = refused(jdk);
            dec = odd(o == b, o == j, b == j);
        }
        return new ThreeWay(rb, rj, pop, att, dec, ours.typeName(),
                bc.typeName(), jdk.typeName());
    }

    private static Attribution odd(boolean weMatchBc, boolean weMatchJdk, boolean bcMatchesJdk)
    {
        if (weMatchBc && weMatchJdk)
        {
            return Attribution.ALL_AGREE;
        }
        if (bcMatchesJdk)
        {
            return Attribution.WE_ARE_ODD;
        }
        if (weMatchJdk)
        {
            return Attribution.BC_IS_ODD;
        }
        if (weMatchBc)
        {
            return Attribution.JDK_IS_ODD;
        }
        return Attribution.ALL_DIFFER;
    }

    /**
     * Did this provider REFUSE the call, at the coarsest level?
     *
     * <p>A throw is a refusal, and so is a verify returning false. Everything
     * else - bytes, no output, a described shape, a verify returning true - is
     * acceptance.
     */
    private static boolean refused(Observation o)
    {
        return o.isThrow() || Boolean.FALSE.equals(o.returnedValue());
    }

    /**
     * A difference for ATTRIBUTION purposes is anything that is not agreement.
     *
     * <p>Deliberately wider than {@link ParityResult#isDivergence()}, which
     * answers "does Megan need to rule on this". Attribution asks the narrower
     * factual question "did these two providers do the same thing", so a
     * {@code MATCH_REFUSED_BY_RETURN} counts as agreement and a
     * {@code BC_ABSENT} - which cannot arise here, both sides having been
     * checked - would not.
     */
    private static boolean isDifference(ParityResult r)
    {
        return r.verdict() != ParityVerdict.MATCH
                && r.verdict() != ParityVerdict.MATCH_ACCEPT
                && r.verdict() != ParityVerdict.MATCH_REFUSED_BY_RETURN;
    }

    public Population population()
    {
        return population;
    }

    /** Who is odd by EXACT behaviour - the type thrown, or the bytes produced. */
    public Attribution attribution()
    {
        return attribution;
    }

    /**
     * Who is odd by DECISION alone - refused against accepted.
     *
     * <p>A second axis, because one field cannot carry both and a single one
     * silently answers whichever question the reader did not ask. Measured on
     * the MessageDigest surface, the two genuinely disagree in both directions:
     *
     * <ul>
     *   <li>{@code update(buf, 0, -1)}: we raise, the JDK raises a DIFFERENT
     *       type, BouncyCastle accepts. By exact behaviour {@code ALL_DIFFER};
     *       by decision {@code BC_IS_ODD}, which is the useful reading and the
     *       one that supports "BouncyCastle alone accepts a negative length".</li>
     *   <li>{@code update(buf, -1, 4)}: all three refuse, so by decision
     *       {@code ALL_AGREE} - and by exact behaviour {@code WE_ARE_ODD},
     *       which is the reading that matters there.</li>
     * </ul>
     *
     * <p>Reporting only the first would have hidden the second finding, and
     * only the second would have hidden the first. A unit test on constructed
     * triples caught this before a live cell ran.
     */
    public Attribution decisionAttribution()
    {
        return decisionAttribution;
    }

    /** Null when BouncyCastle does not serve the name. */
    public ParityResult vsBc()
    {
        return vsBc;
    }

    /** Null when no JDK provider serves the name. */
    public ParityResult vsJdk()
    {
        return vsJdk;
    }

    /** True when this cell needs a ruling: a real difference against a real comparator. */
    public boolean isDivergence()
    {
        return (vsBc != null && vsBc.isDivergence()) || (vsJdk != null && vsJdk.isDivergence());
    }

    public String row(String name, String fault)
    {
        return String.format("%-26s %-32s %-13s type:%-16s dec:%-16s ours=%-30s bc=%-30s jdk=%s",
                name, fault, population, attribution, decisionAttribution,
                simple(ourType), simple(bcType), simple(jdkType));
    }

    private static String simple(String fqcn)
    {
        int i = fqcn.lastIndexOf('.');
        return i < 0 ? fqcn : fqcn.substring(i + 1);
    }
}
