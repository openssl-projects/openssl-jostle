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
 * KeyPairGenerator pinned a 1024-bit floor for generation.
 * {@code BELOW_FLOOR_SIZE_INT} probes the generator half of that pair directly.
 *
 * <p><b>MT-66 removed both jostle-side floors</b> (Megan, 2026-09-05: jostle
 * supports what OpenSSL supports). So 512 is no longer "below ours" on JSL - it
 * is ACCEPTED, because the default provider generates there. The cell is kept
 * and still earns its place: it now measures the divergence in the OTHER
 * direction, against a reference that may still refuse. JSLFIPS keeps a 2048
 * fast-path floor mirroring the module's own, so the same cell refuses there.
 * The floors themselves are pinned by {@code RSAKeySizePinTest} and
 * {@code FIPSRSAKeySizePinTest}.
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
        GENERATE_TWICE,
        /**
         * The FIRST positive-path cell in any MT-31 table.
         *
         * <p>Every other fault here feeds BAD input. That is what let MT-59
         * hide: our generators refused the matching {@code NamedParameterSpec}
         * that both references accept, and no catalogue of bad inputs can see
         * an over-refusal of a good one. So this cell feeds VALID input and a
         * refusal is the finding.
         *
         * <p>Only meaningful where the family has a standard named parameter -
         * see {@link Cell#namedSpec}.
         *
         * <p><b>Read the DECISION axis on this row, not the type axis.</b> All
         * three providers accept, so {@code dec:ALL_AGREE} is the result that
         * matters. The type axis reports {@code ALL_DIFFER} because a produced
         * key is compared by its shape descriptor, and those legitimately
         * differ: the JDK labels these keys {@code EdDSA} / {@code XDH} where we
         * and BouncyCastle use the specific names, and BouncyCastle's PKCS#8
         * carries RFC 8410's optional public key where ours and the JDK's do
         * not (both recorded in MT-53 as legal variations). A refusal by any
         * provider is what this cell exists to catch, and that shows up in the
         * decision axis.
         */
        VALID_MATCHING_SPEC
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
        /**
         * The standard NamedParameterSpec name for this family, or null.
         *
         * <p>Null for RSA/DSA/DH/EC and the PQC families - they select their
         * variant by key size or by algorithm name, so there is no named
         * parameter to offer and the positive-path cell does not apply.
         */
        final String namedSpec;

        Cell(String name, String spiClass, int validSize, boolean sized,
             OperateCrossing.Op op, String opAlgorithm, String keyFactory, String noCrossReason)
        {
            this(name, spiClass, validSize, sized, op, opAlgorithm, keyFactory, noCrossReason, null);
        }

        Cell(String name, String spiClass, int validSize, boolean sized,
             OperateCrossing.Op op, String opAlgorithm, String keyFactory, String noCrossReason,
             String namedSpec)
        {
            this.namedSpec = namedSpec;
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
                OperateCrossing.Op.SIGNATURE, "Ed25519", "Ed25519", null, "Ed25519"));
        c.add(new Cell("X25519", "XECKeyPairGenerator", 0, false,
                OperateCrossing.Op.KEY_AGREEMENT, "X25519", "X25519", null, "X25519"));
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
                    // 512: the smallest size OpenSSL's default provider will
                    // generate. Accepted by JSL since MT-66 removed the
                    // jostle-side floor; refused by JSLFIPS, whose 2048
                    // fast-path mirrors the module.
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
                case VALID_MATCHING_SPEC:
                {
                    // Reflective because NamedParameterSpec is a Java 11 API and
                    // this source set compiles at release 8. Absent below 11, so
                    // the cell reports "absent" there rather than a refusal -
                    // recording a platform gap as a provider divergence would be
                    // the wrong finding.
                    Class<?> nps;
                    try
                    {
                        nps = Class.forName("java.security.spec.NamedParameterSpec");
                    }
                    catch (Throwable preJava11)
                    {
                        return null;
                    }
                    AlgorithmParameterSpec spec = (AlgorithmParameterSpec)
                            nps.getConstructor(String.class).newInstance(cell.namedSpec);
                    g.initialize(spec);
                    return Descriptors.of(g.generateKeyPair()).getBytes("UTF-8");
                }
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
        if (f == Fault.VALID_MATCHING_SPEC)
        {
            return cell.namedSpec != null;
        }
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
        report.assertMeasured(104, cells.size(), 1);

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
