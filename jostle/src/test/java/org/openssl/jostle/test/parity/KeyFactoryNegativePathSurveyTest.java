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

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31 Group B, KeyFactory: 35 names across 10 SPI classes, compared against
 * BouncyCastle and - where it serves the algorithm - the JDK.
 *
 * <h2>Deterministic, so bytes are the baseline</h2>
 *
 * <p>Unlike the two generator surfaces in this group, a KeyFactory decodes a
 * FIXED encoding, so the resulting key's {@code getEncoded()} is byte-comparable
 * across providers. No shape descriptor is needed here.
 *
 * <h2>Delta: the public/private asymmetry</h2>
 *
 * <p>{@code generatePublic} and {@code generatePrivate} take the same declared
 * type, {@code KeySpec}, and each must reject the other's encoding. Nothing in
 * the signature enforces it, so it is the fault most worth measuring on this
 * surface - along with {@code TRAILING_DER}, which is ours to get right:
 * {@code asn1_util.c} returns {@code JO_DER_TRAILING_DATA} where a lenient
 * {@code d2i} would accept the junk.
 */
public class KeyFactoryNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

    enum Fault
    {
        NULL_SPEC_PUBLIC,
        NULL_SPEC_PRIVATE,
        WRONG_SPEC_TYPE_PUBLIC,
        WRONG_SPEC_TYPE_PRIVATE,
        /**
         * An RSA public key with a 12-bit modulus, through the spec the RSA
         * factory genuinely supports.
         *
         * <p>Split out of {@code WRONG_SPEC_TYPE_PUBLIC}, which used an
         * {@code RSAPublicKeySpec} and therefore measured "unsupported spec
         * class" on nine cells and "absurdly small key" on the RSA one - one
         * fault name, two dimensions. It found a real defect by accident; this
         * cell measures it on purpose, and the other now uses a spec class no
         * KeyFactory serves.
         */
        UNDERSIZED_RSA_MODULUS,
        X509_INTO_GENERATE_PRIVATE,
        PKCS8_INTO_GENERATE_PUBLIC,
        TRUNCATED_DER_PUBLIC,
        TRUNCATED_DER_PRIVATE,
        GARBAGE_DER_PUBLIC,
        TRAILING_DER_PUBLIC,
        TRAILING_DER_PRIVATE,
        EMPTY_DER_PUBLIC,
        GET_KEY_SPEC_UNSUPPORTED_CLASS,
        GET_KEY_SPEC_NULL_KEY,
        TRANSLATE_NULL_KEY,
        TRANSLATE_FOREIGN_KEY
    }

    static final class Cell
    {
        final String name;
        final String spiClass;
        final String kpg;

        Cell(String name, String spiClass, String kpg)
        {
            this.name = name;
            this.spiClass = spiClass;
            this.kpg = kpg;
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

    /** One representative per SPI class. Coverage is proved by the census, not by this list. */
    static List<Cell> cells()
    {
        List<Cell> c = new ArrayList<Cell>();
        c.add(new Cell("RSA", "RSAKeyFactorySpi", "RSA"));
        c.add(new Cell("EC", "ECKeyFactorySpi", "EC"));
        c.add(new Cell("DSA", "DSAKeyFactorySpi", "DSA"));
        c.add(new Cell("DH", "DHKeyFactorySpi", "DH"));
        c.add(new Cell("Ed25519", "EdKeyFactorySpi", "Ed25519"));
        c.add(new Cell("X25519", "XECKeyFactorySpi", "X25519"));
        c.add(new Cell("ML-DSA-44", "MLDSAKeyFactorySpiImpl", "ML-DSA-44"));
        c.add(new Cell("ML-KEM-512", "MLKEMKeyFactorySpi", "ML-KEM-512"));
        c.add(new Cell("SLH-DSA-SHA2-128F", "SLHDSAKeyFactorySpi", "SLH-DSA-SHA2-128F"));
        c.add(new Cell("X25519MLKEM768", "MLXKEMKeyFactorySpi", "X25519MLKEM768"));
        return c;
    }

    private static final Map<String, KeyPair> KEYS = new TreeMap<String, KeyPair>();

    private static KeyPair keys(Cell cell) throws Exception
    {
        KeyPair kp = KEYS.get(cell.kpg);
        if (kp == null)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance(cell.kpg, jsl);
            if ("RSA".equals(cell.kpg) || "DSA".equals(cell.kpg) || "DH".equals(cell.kpg))
            {
                g.initialize(2048);
            }
            else if ("EC".equals(cell.kpg))
            {
                g.initialize(new ECGenParameterSpec("P-256"));
            }
            kp = g.generateKeyPair();
            KEYS.put(cell.kpg, kp);
        }
        return kp;
    }

    private static byte[] tamper(byte[] b, int extra)
    {
        byte[] r = new byte[b.length + extra];
        System.arraycopy(b, 0, r, 0, b.length);
        for (int i = b.length; i < r.length; i++)
        {
            r[i] = (byte) 0x2A;
        }
        return r;
    }

    private static Observation run(Provider p, Cell cell, Fault f, KeyPair kp)
    {
        return Observer.observe(() -> {
            KeyFactory kf = KeyFactory.getInstance(cell.name, p);
            byte[] pub = kp.getPublic().getEncoded();
            byte[] prv = kp.getPrivate().getEncoded();
            switch (f)
            {
                case NULL_SPEC_PUBLIC:
                    return kf.generatePublic(null).getEncoded();
                case NULL_SPEC_PRIVATE:
                    return kf.generatePrivate(null).getEncoded();
                case WRONG_SPEC_TYPE_PUBLIC:
                    // A KeySpec class NO KeyFactory serves - DESKeySpec is a
                    // KeySpec, and no asymmetric factory accepts one.
                    return kf.generatePublic(new javax.crypto.spec.DESKeySpec(new byte[8])).getEncoded();
                case WRONG_SPEC_TYPE_PRIVATE:
                    return kf.generatePrivate(new javax.crypto.spec.DESKeySpec(new byte[8])).getEncoded();
                case UNDERSIZED_RSA_MODULUS:
                    return kf.generatePublic(new RSAPublicKeySpec(
                            java.math.BigInteger.valueOf(3233), java.math.BigInteger.valueOf(17))).getEncoded();
                case X509_INTO_GENERATE_PRIVATE:
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(pub)).getEncoded();
                case PKCS8_INTO_GENERATE_PUBLIC:
                    return kf.generatePublic(new X509EncodedKeySpec(prv)).getEncoded();
                case TRUNCATED_DER_PUBLIC:
                    return kf.generatePublic(new X509EncodedKeySpec(
                            java.util.Arrays.copyOf(pub, pub.length - 1))).getEncoded();
                case TRUNCATED_DER_PRIVATE:
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(
                            java.util.Arrays.copyOf(prv, prv.length - 1))).getEncoded();
                case GARBAGE_DER_PUBLIC:
                {
                    byte[] junk = new byte[pub.length];
                    SR.nextBytes(junk);
                    return kf.generatePublic(new X509EncodedKeySpec(junk)).getEncoded();
                }
                case TRAILING_DER_PUBLIC:
                    // Ours to get right: a lenient d2i consumes one TLV and
                    // ignores the rest. JO_DER_TRAILING_DATA exists for this.
                    return kf.generatePublic(new X509EncodedKeySpec(tamper(pub, 4))).getEncoded();
                case TRAILING_DER_PRIVATE:
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(tamper(prv, 4))).getEncoded();
                case EMPTY_DER_PUBLIC:
                    return kf.generatePublic(new X509EncodedKeySpec(new byte[0])).getEncoded();
                case GET_KEY_SPEC_UNSUPPORTED_CLASS:
                {
                    Object o = kf.getKeySpec(kf.generatePublic(new X509EncodedKeySpec(pub)),
                            javax.crypto.spec.DESKeySpec.class);
                    return o == null ? null : new byte[0];
                }
                case GET_KEY_SPEC_NULL_KEY:
                {
                    Object o = kf.getKeySpec(null, X509EncodedKeySpec.class);
                    return o == null ? null : new byte[0];
                }
                case TRANSLATE_NULL_KEY:
                {
                    java.security.Key k = kf.translateKey(null);
                    return k == null ? null : k.getEncoded();
                }
                case TRANSLATE_FOREIGN_KEY:
                {
                    // A SecretKeySpec is not an asymmetric key of any family.
                    java.security.Key k = kf.translateKey(new SecretKeySpec(new byte[16], "AES"));
                    return k == null ? null : k.getEncoded();
                }
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    /** Which faults make sense for a given cell. */
    static boolean applicable(Cell cell, Fault f)
    {
        // An RSAPublicKeySpec is meaningless to a non-RSA factory, where it
        // would silently re-measure WRONG_SPEC_TYPE_PUBLIC under another name.
        return f != Fault.UNDERSIZED_RSA_MODULUS || "RSA".equals(cell.name);
    }

    private static Observation baseline(Provider p, Cell cell, KeyPair kp)
    {
        return Observer.observe(() -> {
            KeyFactory kf = KeyFactory.getInstance(cell.name, p);
            return kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())).getEncoded();
        });
    }

    @Test
    public void surveyKeyFactoryNegativePaths() throws Exception
    {
        SurveyReport report = new SurveyReport("MT-31 KeyFactory negative-path survey");
        List<Cell> cells = cells();

        for (Cell cell : cells)
        {
            KeyPair kp = keys(cell);
            Provider jdk = JdkComparator.forService("KeyFactory", cell.name);

            Observation ourBase = baseline(jsl, cell, kp);
            Observation bcBase = baseline(bc, cell, kp);
            ParityResult base = ExceptionParity.classify(ourBase, bcBase);
            report.note(String.format("%-26s %-32s baseline=%-22s bc=%s jdk=%s",
                    cell.name, "(baseline)", base.verdict(),
                    bcBase.isAbsent() ? "absent" : "present", jdk == null ? "absent" : jdk.getName()));
            if (kp.getPublic().getEncoded() == null)
            {
                // The TLS hybrid KEM keys have no encoding by design, so an
                // encode-decode baseline cannot exist for them. EXPECTED, and
                // reported as such - counting it as a baseline failure would
                // make a documented property look like a defect.
                report.note("        (no encoding by design on this family - not surveyable here)");
                continue;
            }
            if (ourBase.isThrow())
            {
                report.baselineFailed("        OUR BASELINE FAILED: " + ourBase.typeName());
                continue;
            }

            for (Fault f : Fault.values())
            {
                if (!applicable(cell, f))
                {
                    continue;
                }
                Observation o = run(jsl, cell, f, kp);
                Observation b = run(bc, cell, f, kp);
                Observation j = jdk == null ? Observation.absent() : run(jdk, cell, f, kp);
                report.cell(cell.name, f.name(), ThreeWay.classify(o, b, j));
            }
        }
        // Absolute floor, not a fraction of the discovered universe: nine
        // encodable cells times sixteen shared faults, plus the RSA-only one.
        report.assertMeasured(140, cells.size(), 0);
    }

    /** Every registered KeyFactory SPI class reaches a cell. Both directions. */
    @Test
    public void everyKeyFactorySpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"KeyFactory".equals(sv.getType()))
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
        StringBuilder sb = new StringBuilder("\n=== KeyFactory SPI-class census ===\n");
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
                "census found only " + byClass.size() + " KeyFactory SPI classes; not reading the provider");
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered KeyFactory count " + direct);
        Assertions.assertTrue(uncovered.isEmpty(),
                "KeyFactory SPI classes with no survey cell: " + uncovered);
        Set<String> unknown = new HashSet<String>(covered);
        unknown.removeAll(byClass.keySet());
        Assertions.assertTrue(unknown.isEmpty(),
                "survey cells name SPI classes the provider does not register: " + unknown);
    }
}
