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

import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * MT-31, MessageDigest surface: our exception type against BouncyCastle's, for
 * every registered digest and every negative path.
 *
 * <h2>EVERY registered name is surveyed, not a representative sample</h2>
 *
 * <p>The Signature surface carries representative cells because seventy names
 * share eight SPI classes and a negative path is a property of the class. Here
 * twenty-one names share ONE class ({@code MDServiceSPI}), so a
 * class-representative sample would be a single cell - and the interesting
 * variation is per-ALGORITHM instead: the XOFs take a length where the fixed
 * digests do not, {@code MD5-SHA1} is a concatenation, and the SHA-512/t pair
 * are truncations. Twenty-one cells is cheap, so the census asserts coverage of
 * every NAME rather than of every class.
 *
 * <h2>The BouncyCastle name map is real here, and it is RULES not literals</h2>
 *
 * <p>Unlike Signature - where BouncyCastle resolved 63 of 70 names verbatim and
 * a map would have been an identity function - ten of our twenty-one digests
 * are spelled differently by BouncyCastle, because we use OpenSSL's spelling.
 * Measured 2026-09-01, and expressed as four mechanical rules rather than a
 * twenty-one-line table, so the drift surface is four lines:
 *
 * <ul>
 *   <li>{@code SHA2-} to {@code SHA-} (SHA2-256 to SHA-256, and the /224 /256
 *       truncations with it)</li>
 *   <li>{@code RIPEMD-160} to {@code RIPEMD160}</li>
 *   <li>{@code SHAKE-128} / {@code SHAKE-256} to {@code SHAKE128} /
 *       {@code SHAKE256} - note {@code SHAKE128-256} is NOT rewritten, it is
 *       the fixed-output form and BouncyCastle spells it the same</li>
 *   <li>everything else verbatim</li>
 * </ul>
 *
 * <p><b>The map's witness is the positive baseline.</b> Each cell first digests
 * an identical random message on both providers and requires byte equality, so
 * a rule that mapped {@code SHA2-256} onto the wrong BouncyCastle digest could
 * not produce a passing baseline. Verified when the rules were derived: all
 * twenty mapped names agreed byte-for-byte on a 97-byte random input. That is
 * the same argument the Signature surface makes for having no map at all - the
 * naming is witnessed by the operation, never by a separately-audited table.
 */
public class DigestNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

    enum Fault
    {
        NULL_INPUT_UPDATE,
        NEGATIVE_LENGTH_UPDATE,
        NEGATIVE_OFFSET_UPDATE,
        OFFSET_PAST_END_UPDATE,
        LENGTH_PAST_END_UPDATE,
        SHORT_OUTPUT_DIGEST,
        NEGATIVE_OFFSET_DIGEST,
        /** The reset contract: a terminal digest leaves the object reusable. */
        REUSE_AFTER_DIGEST,
        /** An explicit reset mid-message must discard what was absorbed. */
        RESET_MID_MESSAGE
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

    /** Discovered from the provider, never hand-listed. */
    static List<String> names()
    {
        List<String> l = new ArrayList<String>();
        for (Provider.Service sv : jsl.getServices())
        {
            if ("MessageDigest".equals(sv.getType()))
            {
                l.add(sv.getAlgorithm());
            }
        }
        Collections.sort(l);
        return l;
    }

    /** Our name in BouncyCastle's spelling. See the class note for the basis. */
    static String bcName(String ours)
    {
        if (ours.startsWith("SHA2-"))
        {
            return "SHA-" + ours.substring(5);
        }
        if (ours.equals("RIPEMD-160"))
        {
            return "RIPEMD160";
        }
        if (ours.equals("SHAKE-128") || ours.equals("SHAKE-256"))
        {
            return ours.replace("SHAKE-", "SHAKE");
        }
        return ours;
    }

    private static MessageDigest md(Provider p, String name) throws Exception
    {
        return MessageDigest.getInstance(p == jsl ? name : bcName(name), p);
    }

    private static Observation baseline(Provider p, String name, byte[] msg)
    {
        return Observer.observe(() -> md(p, name).digest(msg));
    }

    private static Observation applyFault(Provider p, String name, Fault f, byte[] msg)
    {
        return Observer.observe(() -> {
            MessageDigest d = md(p, name);
            switch (f)
            {
                case NULL_INPUT_UPDATE:
                    d.update((byte[]) null);
                    return d.digest();
                case NEGATIVE_LENGTH_UPDATE:
                    d.update(msg, 0, -1);
                    return d.digest();
                case NEGATIVE_OFFSET_UPDATE:
                    d.update(msg, -1, 4);
                    return d.digest();
                case OFFSET_PAST_END_UPDATE:
                    // boundary + 1, not an arbitrary large value.
                    d.update(msg, msg.length + 1, 0);
                    return d.digest();
                case LENGTH_PAST_END_UPDATE:
                    d.update(msg, 0, msg.length + 1);
                    return d.digest();
                case SHORT_OUTPUT_DIGEST:
                {
                    d.update(msg);
                    byte[] out = new byte[Math.max(0, d.getDigestLength() - 1)];
                    d.digest(out, 0, out.length);
                    return out;
                }
                case NEGATIVE_OFFSET_DIGEST:
                {
                    d.update(msg);
                    byte[] out = new byte[Math.max(1, d.getDigestLength())];
                    d.digest(out, -1, out.length);
                    return out;
                }
                case REUSE_AFTER_DIGEST:
                    // Contract cell, not a refusal probe: a terminal digest
                    // resets, so the second answer must equal a fresh one. Both
                    // providers return the SAME bytes here when correct, so a
                    // byte comparison is meaningful - unlike the randomised
                    // signature case, where it measured randomisation instead.
                    d.update(msg);
                    d.digest();
                    d.update(msg);
                    return d.digest();
                case RESET_MID_MESSAGE:
                    d.update(msg);
                    d.reset();
                    d.update(msg);
                    return d.digest();
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    @Test
    public void surveyDigestNegativePaths()
    {
        List<String> rows = new ArrayList<String>();
        Map<ParityVerdict, Integer> tally = new EnumMap<ParityVerdict, Integer>(ParityVerdict.class);
        int measured = 0;
        int noBaseline = 0;
        List<String> names = names();

        for (String name : names)
        {
            byte[] msg = new byte[64 + SR.nextInt(64)];
            SR.nextBytes(msg);

            Observation ourBase = baseline(jsl, name, msg);
            Observation bcBase = baseline(bc, name, msg);
            ParityResult base = ExceptionParity.classify(ourBase, bcBase);
            if (base.verdict() == ParityVerdict.BC_ABSENT)
            {
                rows.add(row(name, "(baseline)", base));
                bump(tally, ParityVerdict.BC_ABSENT);
                continue;
            }
            rows.add(row(name, "(baseline)", base));
            bump(tally, base.verdict());
            if (base.verdict() != ParityVerdict.MATCH_ACCEPT)
            {
                noBaseline++;
                continue;
            }

            for (Fault f : Fault.values())
            {
                ParityResult r = ExceptionParity.classify(
                        applyFault(jsl, name, f, msg), applyFault(bc, name, f, msg));
                rows.add(row(name, f.name(), r));
                bump(tally, r.verdict());
                measured++;
            }
        }

        StringBuilder sb = new StringBuilder("\n=== MT-31 MessageDigest negative-path survey ===\n");
        for (String r : rows)
        {
            sb.append(r).append('\n');
        }
        sb.append("--- tally ---\n");
        for (Map.Entry<ParityVerdict, Integer> e : tally.entrySet())
        {
            sb.append(String.format("  %-26s %d%n", e.getKey(), e.getValue()));
        }
        System.out.println(sb);

        Assertions.assertTrue(measured >= names.size() * (Fault.values().length - 1),
                "survey measured only " + measured + " fault cells across " + names.size()
                        + " digests; it is not measuring the surface");
        Assertions.assertTrue(noBaseline * 4 < names.size(),
                noBaseline + " of " + names.size() + " digests had no working baseline");
    }

    /**
     * Every registered digest reaches the survey.
     *
     * <p>Trivial only because {@link #names()} discovers them - which is the
     * point: a hand-written list is what makes this test worth having, and not
     * having one is what makes it pass. It still earns its place by pinning the
     * DISCOVERY, so a future filter added to {@code names()} that silently drops
     * a family fails here.
     */
    @Test
    public void everyRegisteredDigestIsSurveyed()
    {
        int registered = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if ("MessageDigest".equals(sv.getType()))
            {
                registered++;
            }
        }
        Assertions.assertTrue(registered >= 15,
                "only " + registered + " MessageDigest services found; not reading the provider");
        Assertions.assertEquals(registered, names().size(),
                "names() dropped " + (registered - names().size()) + " registered digests");
    }

    private static void bump(Map<ParityVerdict, Integer> m, ParityVerdict v)
    {
        Integer n = m.get(v);
        m.put(v, n == null ? 1 : n + 1);
    }

    private static String row(String name, String fault, ParityResult r)
    {
        String head = String.format("%-14s %-24s %-26s ours=%-32s bc=%-32s %s",
                name, fault, r.verdict(), simple(r.ourType()), simple(r.bcType()), r.qualifier());
        if (!r.isDivergence())
        {
            return head;
        }
        return head + "\n" + String.format("%-14s %-24s   ours: %s%n%-14s %-24s     bc: %s",
                "", "", blank(r.ourMessage()), "", "", blank(r.bcMessage()));
    }

    private static String blank(String s)
    {
        return s == null || s.isEmpty() ? "(no message)" : s;
    }

    private static String simple(String fqcn)
    {
        int i = fqcn.lastIndexOf('.');
        return i < 0 ? fqcn : fqcn.substring(i + 1);
    }
}
