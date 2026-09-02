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

import org.junit.jupiter.api.Assertions;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Row collection, three-population tallies, and the non-vacuity floor, shared
 * by the four Group B surveys.
 *
 * <p>Shared because it is genuinely the same in all four - and ONLY this is.
 * Each survey keeps its own cell table and its own fault catalogue, because
 * those are what differ and folding them together would produce one grand
 * catalogue nobody can read.
 *
 * <p>{@link #assertMeasured} is the non-vacuity floor and it takes an ABSOLUTE
 * expected count, deliberately. A floor expressed relative to the survey's own
 * discovered universe shrinks WITH that universe: sabotaging digest discovery
 * to drop the SHAKE family left the digest survey green because its floor was
 * {@code names().size()}-relative. Only a fixed number, or a separate discovery
 * pin, can see a universe shrinking.
 */
public final class SurveyReport
{
    private final String title;
    private final List<String> rows = new ArrayList<String>();
    private final Map<ThreeWay.Population, Integer> populations =
            new EnumMap<ThreeWay.Population, Integer>(ThreeWay.Population.class);
    private final Map<ThreeWay.Attribution, Integer> attributions =
            new EnumMap<ThreeWay.Attribution, Integer>(ThreeWay.Attribution.class);
    private final Map<ThreeWay.Attribution, Integer> decisions =
            new EnumMap<ThreeWay.Attribution, Integer>(ThreeWay.Attribution.class);
    private final List<String> divergences = new ArrayList<String>();
    private int measured;
    private int noBaseline;

    public SurveyReport(String title)
    {
        this.title = title;
    }

    public void note(String line)
    {
        rows.add(line);
    }

    public void baselineFailed(String line)
    {
        rows.add(line);
        noBaseline++;
    }

    public void cell(String name, String fault, ThreeWay r)
    {
        measured++;
        String row = r.row(name, fault);
        rows.add(row);
        bump(populations, r.population());
        bump(attributions, r.attribution());
        bump(decisions, r.decisionAttribution());
        if (r.isDivergence())
        {
            StringBuilder d = new StringBuilder(row);
            if (r.vsBc() != null && r.vsBc().isDivergence())
            {
                d.append("\n        vs BC : ").append(r.vsBc().verdict())
                        .append(" ours[").append(blank(r.vsBc().ourMessage()))
                        .append("] bc[").append(blank(r.vsBc().bcMessage())).append(']');
            }
            if (r.vsJdk() != null && r.vsJdk().isDivergence())
            {
                d.append("\n        vs JDK: ").append(r.vsJdk().verdict())
                        .append(" jdk[").append(blank(r.vsJdk().bcMessage())).append(']');
            }
            divergences.add(d.toString());
        }
    }

    public int measured()
    {
        return measured;
    }

    public int noBaseline()
    {
        return noBaseline;
    }

    /** Print, then assert the floor. The floor is ABSOLUTE - see the class note. */
    public void assertMeasured(int atLeast, int cells, int baselineFailuresAllowed)
    {
        StringBuilder sb = new StringBuilder("\n=== ").append(title).append(" ===\n");
        for (String r : rows)
        {
            sb.append(r).append('\n');
        }
        if (!divergences.isEmpty())
        {
            sb.append("--- divergences, with messages ---\n");
            for (String d : divergences)
            {
                sb.append(d).append('\n');
            }
        }
        sb.append("--- populations ---\n");
        int popSum = 0;
        for (Map.Entry<ThreeWay.Population, Integer> e : populations.entrySet())
        {
            sb.append(String.format("  %-16s %d%n", e.getKey(), e.getValue()));
            popSum += e.getValue();
        }
        sb.append("--- attribution by exact behaviour ---\n");
        for (Map.Entry<ThreeWay.Attribution, Integer> e : attributions.entrySet())
        {
            sb.append(String.format("  %-20s %d%n", e.getKey(), e.getValue()));
        }
        sb.append("--- attribution by decision ---\n");
        for (Map.Entry<ThreeWay.Attribution, Integer> e : decisions.entrySet())
        {
            sb.append(String.format("  %-20s %d%n", e.getKey(), e.getValue()));
        }
        sb.append(String.format("  measured=%d  divergences=%d  cells=%d  no-baseline=%d%n",
                measured, divergences.size(), cells, noBaseline));
        System.out.println(sb);

        // The report asserts its own sum: a tally that disagrees with the row
        // count is the one document that has to be exact.
        Assertions.assertEquals(measured, popSum,
                "population tally " + popSum + " does not equal the measured cell count " + measured);
        Assertions.assertTrue(measured >= atLeast,
                title + " measured only " + measured + " cells, expected at least " + atLeast
                        + "; it is not measuring the surface");
        Assertions.assertTrue(noBaseline <= baselineFailuresAllowed,
                title + ": " + noBaseline + " of " + cells + " cells had no working baseline"
                        + " (at most " + baselineFailuresAllowed + " tolerated)");
    }

    private static void bump(Map<ThreeWay.Population, Integer> m, ThreeWay.Population k)
    {
        Integer n = m.get(k);
        m.put(k, n == null ? 1 : n + 1);
    }

    private static void bump(Map<ThreeWay.Attribution, Integer> m, ThreeWay.Attribution k)
    {
        Integer n = m.get(k);
        m.put(k, n == null ? 1 : n + 1);
    }

    private static String blank(String s)
    {
        return s == null || s.isEmpty() ? "(no message)" : s;
    }
}
