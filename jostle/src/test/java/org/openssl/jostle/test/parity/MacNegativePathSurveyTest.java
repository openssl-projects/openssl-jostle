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

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * MT-31, Mac surface: our exception type against BouncyCastle's, for every
 * registered MAC and every negative path.
 *
 * <p>Twenty names, one SPI class ({@code MacServiceSPI}), so - as with
 * MessageDigest - the census covers every NAME rather than every class, and the
 * names are DISCOVERED from {@code getServices()} rather than listed.
 *
 * <h2>Init shape is measured, not assumed</h2>
 *
 * <p>Probed on both providers 2026-09-01: nineteen of twenty take a bare
 * 32-byte key, and only {@code AESGMAC} requires an IV. Both providers produce
 * identical tag lengths for every shared name. {@code HMACMD5SHA1} - the
 * TLS 1.0 PRF combination - has no BouncyCastle name and lands as
 * {@code BC_ABSENT} rather than being dropped from the table.
 *
 * <p>The init shape is derived by TRYING the bare key and falling back to the
 * IV form, per cell and per provider, rather than being tabulated. A table
 * would be a second source of truth about a fact the providers already answer,
 * and it would silently mis-shape a future MAC that changes its requirement.
 */
public class MacNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

    enum Fault
    {
        NULL_KEY,
        EMPTY_KEY,
        WRONG_ALGORITHM_KEY,
        UNINITIALISED_UPDATE,
        UNINITIALISED_DOFINAL,
        FOREIGN_PARAM_SPEC,
        NEGATIVE_LENGTH_UPDATE,
        NEGATIVE_OFFSET_UPDATE,
        OFFSET_PAST_END_UPDATE,
        SHORT_OUTPUT_DOFINAL,
        /** A terminal doFinal resets; a MAC is deterministic so bytes compare. */
        REUSE_AFTER_DOFINAL,
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

    static List<String> names()
    {
        List<String> l = new ArrayList<String>();
        for (Provider.Service sv : jsl.getServices())
        {
            if ("Mac".equals(sv.getType()))
            {
                l.add(sv.getAlgorithm());
            }
        }
        Collections.sort(l);
        return l;
    }

    /**
     * Init with a bare key, falling back to the IV form. Measured per call, so
     * no table can go stale against a MAC that changes its requirement.
     */
    private static void init(Mac m, String name, byte[] key, byte[] iv) throws Exception
    {
        try
        {
            m.init(new SecretKeySpec(key, name));
        }
        catch (Exception bare)
        {
            m.init(new SecretKeySpec(key, name), new IvParameterSpec(iv));
        }
    }

    private static Observation baseline(Provider p, String name, byte[] key, byte[] iv, byte[] msg)
    {
        return Observer.observe(() -> {
            Mac m = Mac.getInstance(name, p);
            init(m, name, key, iv);
            m.update(msg);
            return m.doFinal();
        });
    }

    private static Observation applyFault(Provider p, String name, Fault f,
                                          byte[] key, byte[] iv, byte[] msg)
    {
        return Observer.observe(() -> {
            Mac m = Mac.getInstance(name, p);
            switch (f)
            {
                case NULL_KEY:
                    m.init(null);
                    return null;
                case EMPTY_KEY:
                    init(m, name, new byte[0], iv);
                    return null;
                case WRONG_ALGORITHM_KEY:
                    // Same bytes, a foreign algorithm label. Isolates the
                    // algorithm check from every length and parameter check.
                    m.init(new SecretKeySpec(key, "NotAnAlgorithm"));
                    return null;
                case UNINITIALISED_UPDATE:
                    m.update(msg);
                    return null;
                case UNINITIALISED_DOFINAL:
                    return m.doFinal();
                case FOREIGN_PARAM_SPEC:
                    m.init(new SecretKeySpec(key, name),
                            (AlgorithmParameterSpec) new PBEParameterSpec(new byte[8], 1000));
                    return null;
                case NEGATIVE_LENGTH_UPDATE:
                    init(m, name, key, iv);
                    m.update(msg, 0, -1);
                    return m.doFinal();
                case NEGATIVE_OFFSET_UPDATE:
                    init(m, name, key, iv);
                    m.update(msg, -1, 4);
                    return m.doFinal();
                case OFFSET_PAST_END_UPDATE:
                    init(m, name, key, iv);
                    m.update(msg, msg.length + 1, 0);
                    return m.doFinal();
                case SHORT_OUTPUT_DOFINAL:
                {
                    init(m, name, key, iv);
                    m.update(msg);
                    byte[] out = new byte[Math.max(0, m.getMacLength() - 1)];
                    m.doFinal(out, 0);
                    return out;
                }
                case REUSE_AFTER_DOFINAL:
                    init(m, name, key, iv);
                    m.update(msg);
                    m.doFinal();
                    m.update(msg);
                    return m.doFinal();
                case RESET_MID_MESSAGE:
                    init(m, name, key, iv);
                    m.update(msg);
                    m.reset();
                    m.update(msg);
                    return m.doFinal();
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    @Test
    public void surveyMacNegativePaths()
    {
        List<String> rows = new ArrayList<String>();
        Map<ParityVerdict, Integer> tally = new EnumMap<ParityVerdict, Integer>(ParityVerdict.class);
        int measured = 0;
        int noBaseline = 0;
        List<String> names = names();

        for (String name : names)
        {
            byte[] key = new byte[32];
            SR.nextBytes(key);
            byte[] iv = new byte[12];
            SR.nextBytes(iv);
            byte[] msg = new byte[64 + SR.nextInt(64)];
            SR.nextBytes(msg);

            Observation ourBase = baseline(jsl, name, key, iv, msg);
            Observation bcBase = baseline(bc, name, key, iv, msg);
            ParityResult base = ExceptionParity.classify(ourBase, bcBase);
            rows.add(row(name, "(baseline)", base));
            bump(tally, base.verdict());
            if (base.verdict() == ParityVerdict.BC_ABSENT)
            {
                continue;
            }
            if (base.verdict() != ParityVerdict.MATCH_ACCEPT)
            {
                noBaseline++;
                continue;
            }

            for (Fault f : Fault.values())
            {
                ParityResult r = ExceptionParity.classify(
                        applyFault(jsl, name, f, key, iv, msg),
                        applyFault(bc, name, f, key, iv, msg));
                rows.add(row(name, f.name(), r));
                bump(tally, r.verdict());
                measured++;
            }
        }

        StringBuilder sb = new StringBuilder("\n=== MT-31 Mac negative-path survey ===\n");
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

        Assertions.assertTrue(measured >= (names.size() - 2) * Fault.values().length,
                "survey measured only " + measured + " fault cells across " + names.size()
                        + " MACs; it is not measuring the surface");
        Assertions.assertTrue(noBaseline * 4 < names.size(),
                noBaseline + " of " + names.size() + " MACs had no working baseline");
    }

    @Test
    public void everyRegisteredMacIsSurveyed()
    {
        int registered = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if ("Mac".equals(sv.getType()))
            {
                registered++;
            }
        }
        Assertions.assertTrue(registered >= 15,
                "only " + registered + " Mac services found; not reading the provider");
        Assertions.assertEquals(registered, names().size(),
                "names() dropped " + (registered - names().size()) + " registered MACs");
    }

    private static void bump(Map<ParityVerdict, Integer> m, ParityVerdict v)
    {
        Integer n = m.get(v);
        m.put(v, n == null ? 1 : n + 1);
    }

    private static String row(String name, String fault, ParityResult r)
    {
        String head = String.format("%-16s %-24s %-26s ours=%-32s bc=%-32s %s",
                name, fault, r.verdict(), simple(r.ourType()), simple(r.bcType()), r.qualifier());
        if (!r.isDivergence())
        {
            return head;
        }
        return head + "\n" + String.format("%-16s %-24s   ours: %s%n%-16s %-24s     bc: %s",
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
