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

import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31, KeyAgreement surface: our exception type against BouncyCastle's.
 *
 * <h2>The catalogue is PHASE-shaped and shares nothing with a digest's</h2>
 *
 * <p>KeyAgreement is the one Group A surface whose faults are not "bad bytes in,
 * what comes out" - it is a small state machine (init, doPhase, generateSecret)
 * and most of its negative paths are ORDERING faults rather than value faults.
 * The observation shapes are the same as the other two surfaces, which is why
 * this shares their machinery; the fault catalogue is entirely its own.
 *
 * <h2>Two cell shapes, measured not assumed</h2>
 *
 * <p>The raw agreements (DH, ECDH, X25519, X448, XDH) answer
 * {@code generateSecret()}. The KDF-bearing ones (ECDHwithSHAnnnKDF,
 * DHwithRFC2631KDF) deliberately SEAL that method - the pre-KDF shared secret
 * must never escape, a BouncyCastle-parity property already pinned by
 * {@code KeyAgreementKDFTest} - and answer {@code generateSecret(wrapOid)}
 * instead. A cell therefore carries the algorithm name to ask for, or null for
 * the raw form.
 *
 * <p>This was got wrong first: the shape probe tried {@code generateSecret()}
 * then {@code generateSecret("AES")}, and reported both KDF families as
 * outright failures on our side. "AES" is not a wrap algorithm the KDF can size
 * a key for, so the second attempt raised {@code NoSuchAlgorithmException} and
 * the cell looked broken. The sealing is deliberate and the wrap OID is the
 * documented way in - a harness fault, caught before it reached a report, and
 * the third of this arc.
 */
public class KeyAgreementNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();
    /** id-aes256-wrap: what the KDF variants size their derived key from. */
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";

    enum Fault
    {
        NULL_KEY_INIT,
        WRONG_FAMILY_KEY_INIT,
        PUBLIC_KEY_FOR_INIT,
        FOREIGN_PARAM_SPEC_INIT,
        DOPHASE_BEFORE_INIT,
        GENERATE_SECRET_BEFORE_INIT,
        GENERATE_SECRET_BEFORE_DOPHASE,
        NULL_PUBLIC_KEY_DOPHASE,
        WRONG_FAMILY_PUBLIC_KEY_DOPHASE,
        OWN_PUBLIC_KEY_DOPHASE,
        DOPHASE_NOT_LAST_THEN_GENERATE,
        GENERATE_SECRET_TWICE,
        SHORT_OUTPUT_GENERATE_SECRET
    }

    /** One agreement under survey. */
    static final class Cell
    {
        final String name;
        final String spiClass;
        final String kpgAlgorithm;
        final String bcKeyFactory;
        /** Algorithm to ask generateSecret for, or null to use the raw form. */
        final String secretAlgorithm;

        Cell(String name, String spiClass, String kpg, String kf, String secretAlgorithm)
        {
            this.name = name;
            this.spiClass = spiClass;
            this.kpgAlgorithm = kpg;
            this.bcKeyFactory = kf;
            this.secretAlgorithm = secretAlgorithm;
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
        c.add(new Cell("DH", "DHKeyAgreementSpi", "DH", "DH", null));
        c.add(new Cell("DHWITHRFC2631KDF", "DHWithKDFKeyAgreementSpi", "DH", "DH", AES256_WRAP));
        c.add(new Cell("ECDH", "ECDHKeyAgreementSpi", "EC", "EC", null));
        c.add(new Cell("ECDHWITHSHA256KDF", "ECWithKDFKeyAgreementSpi", "EC", "EC", AES256_WRAP));
        c.add(new Cell("X25519", "XDHKeyAgreementSpi", "X25519", "X25519", null));
        c.add(new Cell("X448", "XDHKeyAgreementSpi", "X448", "X448", null));
        c.add(new Cell("XDH", "XDHKeyAgreementSpi", "X25519", "XDH", null));
        return c;
    }

    // ------------------------------------------------------------------

    static final class Pair
    {
        final KeyPair a;
        final KeyPair b;
        final PrivateKey bcA;
        final PublicKey bcB;
        final PublicKey bcAPub;

        Pair(KeyPair a, KeyPair b, PrivateKey bcA, PublicKey bcB, PublicKey bcAPub)
        {
            this.a = a;
            this.b = b;
            this.bcA = bcA;
            this.bcB = bcB;
            this.bcAPub = bcAPub;
        }

        PrivateKey priv(Provider p)
        {
            return p == jsl ? a.getPrivate() : bcA;
        }

        PublicKey peer(Provider p)
        {
            return p == jsl ? b.getPublic() : bcB;
        }

        PublicKey own(Provider p)
        {
            return p == jsl ? a.getPublic() : bcAPub;
        }
    }

    private static final Map<String, Pair> CACHE = new TreeMap<String, Pair>();

    private static Pair keys(Cell cell) throws Exception
    {
        Pair p = CACHE.get(cell.kpgAlgorithm + "/" + cell.bcKeyFactory);
        if (p != null)
        {
            return p;
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(cell.kpgAlgorithm, jsl);
        if ("DH".equals(cell.kpgAlgorithm))
        {
            g.initialize(2048);
        }
        else if ("EC".equals(cell.kpgAlgorithm))
        {
            g.initialize(new ECGenParameterSpec("P-256"));
        }
        KeyPair a = g.generateKeyPair();
        KeyPair b = g.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(cell.bcKeyFactory, bc);
        p = new Pair(a, b,
                kf.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded())),
                kf.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded())),
                kf.generatePublic(new X509EncodedKeySpec(a.getPublic().getEncoded())));
        CACHE.put(cell.kpgAlgorithm + "/" + cell.bcKeyFactory, p);
        return p;
    }

    /** A keypair of a different family, per provider. */
    private static Pair foreign(Cell cell) throws Exception
    {
        return keys("EC".equals(cell.kpgAlgorithm)
                ? new Cell("x", "x", "X25519", "X25519", null)
                : new Cell("x", "x", "EC", "EC", null));
    }

    private static byte[] finish(KeyAgreement k, Cell cell) throws Exception
    {
        return cell.secretAlgorithm == null
                ? k.generateSecret()
                : k.generateSecret(cell.secretAlgorithm).getEncoded();
    }

    private static Observation baseline(Provider p, Cell cell, Pair keys)
    {
        return Observer.observe(() -> {
            KeyAgreement k = KeyAgreement.getInstance(cell.name, p);
            k.init(keys.priv(p));
            k.doPhase(keys.peer(p), true);
            return finish(k, cell);
        });
    }

    private static Observation applyFault(Provider p, Cell cell, Fault f, Pair keys) throws Exception
    {
        Pair other = foreign(cell);
        return Observer.observe(() -> {
            KeyAgreement k = KeyAgreement.getInstance(cell.name, p);
            switch (f)
            {
                case NULL_KEY_INIT:
                    k.init((PrivateKey) null);
                    return null;
                case WRONG_FAMILY_KEY_INIT:
                    k.init(other.priv(p));
                    return null;
                case PUBLIC_KEY_FOR_INIT:
                    k.init((PrivateKey) (Object) keys.own(p));
                    return null;
                case FOREIGN_PARAM_SPEC_INIT:
                    k.init(keys.priv(p), new IvParameterSpec(new byte[16]));
                    return null;
                case DOPHASE_BEFORE_INIT:
                    k.doPhase(keys.peer(p), true);
                    return null;
                case GENERATE_SECRET_BEFORE_INIT:
                    return finish(k, cell);
                case GENERATE_SECRET_BEFORE_DOPHASE:
                    k.init(keys.priv(p));
                    return finish(k, cell);
                case NULL_PUBLIC_KEY_DOPHASE:
                    k.init(keys.priv(p));
                    k.doPhase(null, true);
                    return null;
                case WRONG_FAMILY_PUBLIC_KEY_DOPHASE:
                    k.init(keys.priv(p));
                    k.doPhase(other.peer(p), true);
                    return null;
                case OWN_PUBLIC_KEY_DOPHASE:
                    // Not malformed - a caller agreeing with itself. Legal
                    // arithmetic, so a refusal here would be a policy choice
                    // and worth knowing about on both sides.
                    k.init(keys.priv(p));
                    k.doPhase(keys.own(p), true);
                    return finish(k, cell);
                case DOPHASE_NOT_LAST_THEN_GENERATE:
                    k.init(keys.priv(p));
                    k.doPhase(keys.peer(p), false);
                    return finish(k, cell);
                case GENERATE_SECRET_TWICE:
                    k.init(keys.priv(p));
                    k.doPhase(keys.peer(p), true);
                    finish(k, cell);
                    return finish(k, cell);
                case SHORT_OUTPUT_GENERATE_SECRET:
                {
                    k.init(keys.priv(p));
                    k.doPhase(keys.peer(p), true);
                    byte[] out = new byte[1];
                    k.generateSecret(out, 0);
                    return out;
                }
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    @Test
    public void surveyKeyAgreementNegativePaths() throws Exception
    {
        List<String> rows = new ArrayList<String>();
        Map<ParityVerdict, Integer> tally = new EnumMap<ParityVerdict, Integer>(ParityVerdict.class);
        int measured = 0;
        int noBaseline = 0;

        for (Cell cell : cells())
        {
            Pair keys = keys(cell);
            Observation ourBase = baseline(jsl, cell, keys);
            Observation bcBase = baseline(bc, cell, keys);
            ParityResult base = ExceptionParity.classify(ourBase, bcBase);
            rows.add(row(cell, "(baseline)", base));
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
                        applyFault(jsl, cell, f, keys), applyFault(bc, cell, f, keys));
                rows.add(row(cell, f.name(), r));
                bump(tally, r.verdict());
                measured++;
            }
        }

        StringBuilder sb = new StringBuilder("\n=== MT-31 KeyAgreement negative-path survey ===\n");
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

        Assertions.assertTrue(measured >= 60,
                "survey measured only " + measured + " fault cells; it is not measuring the surface");
        Assertions.assertTrue(noBaseline * 3 < cells().size(),
                noBaseline + " of " + cells().size() + " agreements had no working baseline");
    }

    /** Every registered KeyAgreement SPI class reaches a cell. Both directions. */
    @Test
    public void everyKeyAgreementSpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"KeyAgreement".equals(sv.getType()))
            {
                continue;
            }
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
        StringBuilder sb = new StringBuilder("\n=== KeyAgreement SPI-class census ===\n");
        List<String> uncovered = new ArrayList<String>();
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

        Assertions.assertTrue(byClass.size() >= 4,
                "census found only " + byClass.size() + " KeyAgreement SPI classes; not reading the provider");
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if ("KeyAgreement".equals(sv.getType()))
            {
                direct++;
            }
        }
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered KeyAgreement count " + direct);
        Assertions.assertTrue(uncovered.isEmpty(),
                "KeyAgreement SPI classes with no survey cell: " + uncovered);
        Set<String> unknown = new HashSet<String>(covered);
        unknown.removeAll(byClass.keySet());
        Assertions.assertTrue(unknown.isEmpty(),
                "survey cells name SPI classes the provider does not register: " + unknown);
    }

    private static void bump(Map<ParityVerdict, Integer> m, ParityVerdict v)
    {
        Integer n = m.get(v);
        m.put(v, n == null ? 1 : n + 1);
    }

    private static String row(Cell cell, String fault, ParityResult r)
    {
        String head = String.format("%-20s %-32s %-26s ours=%-32s bc=%-32s %s",
                cell.name, fault, r.verdict(), simple(r.ourType()), simple(r.bcType()), r.qualifier());
        if (!r.isDivergence())
        {
            return head;
        }
        return head + "\n" + String.format("%-20s %-32s   ours: %s%n%-20s %-32s     bc: %s",
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
