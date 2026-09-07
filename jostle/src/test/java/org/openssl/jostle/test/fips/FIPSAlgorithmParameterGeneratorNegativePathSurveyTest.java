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

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.parity.AlgorithmParameterGeneratorNegativePathSurveyTest;
import org.openssl.jostle.test.parity.JdkComparator;
import org.openssl.jostle.test.parity.Observation;
import org.openssl.jostle.test.parity.Observer;
import org.openssl.jostle.test.parity.SurveyReport;
import org.openssl.jostle.test.parity.ThreeWay;

import java.security.AlgorithmParameterGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

/**
 * The JSLFIPS half of the Group C {@code AlgorithmParameterGenerator} survey.
 *
 * <p>Required by the both-classes rule: the base survey compares JSL against
 * BouncyCastle and the JDK and drives {@code libinterface_{jni,ffi}} through the
 * base {@code OSSL_LIB_CTX}; this one drives
 * {@code libinterface_fips_{jni,ffi}} through the FIPS lib ctx. Neither
 * substitutes for the other, and a JSLFIPS-only defect is invisible to the base
 * class.
 *
 * <h2>The catalogue is REUSED, not copied</h2>
 *
 * <p>{@link AlgorithmParameterGeneratorNegativePathSurveyTest.Fault} and its
 * {@code applyFault} are shared. A second copy of the nine faults would be a
 * second source of truth about the same question, and the two would drift the
 * first time either was edited. What differs between the two classes is the
 * provider under test and the module gate - nothing else, so nothing else is
 * duplicated.
 *
 * <h2>Both SPI classes are shared with JSL, which is the thing to notice</h2>
 *
 * <p>{@code ProvFIPSDH} and {@code ProvFIPSDSA} register the SAME
 * {@code DHAlgorithmParameterGenerator} / {@code DSAAlgorithmParameterGenerator}
 * classes the base provider uses - unlike {@code ProvFIPSRSA}, which constructs
 * its generator with a different floor. So the Java-layer size rules measured by
 * the base survey (DH 1024..8192 in multiples of 64; DSA the FIPS 186-4 &sect;4.2
 * set {1024, 2048, 3072}) apply identically here, and any divergence this table
 * shows against the base one comes from the MODULE, not from the SPI.
 *
 * <p>{@code GENERATE_NO_INIT} is where that can bite: it is the only cell that
 * reaches the module, and a module which gates DSA generation refuses it there
 * while the base provider accepts. The survey RECORDS whatever it finds rather
 * than asserting a module's answer, per the two-supported-modules rule.
 */
public class FIPSAlgorithmParameterGeneratorNegativePathSurveyTest
{
    private static Provider fips;
    private static Provider bc;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
    }

    /** Read LIVE from the FIPS provider, never from the base provider's set. */
    static List<String> names()
    {
        List<String> l = new ArrayList<String>();
        for (Provider.Service sv : fips.getServices())
        {
            if (AlgorithmParameterGeneratorNegativePathSurveyTest.TYPE.equals(sv.getType())
                    && sv.getAlgorithm().indexOf('.') < 0)
            {
                l.add(sv.getAlgorithm());
            }
        }
        Collections.sort(l);
        return l;
    }

    @Test
    public void surveyFipsAlgorithmParameterGeneratorNegativePaths()
    {
        SurveyReport report = new SurveyReport(
                "MT-31 Group C JSLFIPS AlgorithmParameterGenerator negative-path survey");
        List<String> names = names();
        String type = AlgorithmParameterGeneratorNegativePathSurveyTest.TYPE;

        for (String name : names)
        {
            Provider jdk = JdkComparator.forService(type, name);
            report.note(String.format("%-8s (comparability)  bc=%s  jdk=%s", name,
                    bc.getService(type, name) == null ? "absent" : "present",
                    jdk == null ? "absent" : jdk.getName()));

            for (AlgorithmParameterGeneratorNegativePathSurveyTest.Fault f
                    : AlgorithmParameterGeneratorNegativePathSurveyTest.Fault.values())
            {
                report.cell(name, f.name(), ThreeWay.classify(
                        AlgorithmParameterGeneratorNegativePathSurveyTest.applyFault(fips, name, f),
                        bc.getService(type, name) == null ? Observation.absent()
                                : AlgorithmParameterGeneratorNegativePathSurveyTest.applyFault(bc, name, f),
                        jdk == null ? Observation.absent()
                                : AlgorithmParameterGeneratorNegativePathSurveyTest.applyFault(jdk, name, f)));
            }
        }
        report.assertMeasured(28, names.size(), 0);
    }

    /**
     * The FIPS-side size rule is DIFFERENT from the base provider's, and this
     * pins it PER MODULE.
     *
     * <p>Arc C dropped the base floor to OpenSSL's 512 with no shape rule. A
     * validated module does not offer that: measured through
     * {@code FIPSNISelector} with the Java floor bypassed, the 3.1.2 module
     * accepts DSA paramgen at 2048 and 3072 ONLY, refusing 511, 512, 1024 and
     * 4096 with {@code ffc_validate} errors - it enforces the FIPS 186-4
     * &sect;4.2 (L, N) pairs. So {@code ProvFIPSDSA} constructs the generator
     * with that set, on the {@code ProvFIPSRSA} precedent, and the refusal
     * happens at {@code init} rather than inside the module at generate.
     *
     * <p>The 3.5.8 module gates DSA generation entirely, so no size is
     * observable there and the refusal arrives as
     * {@code ProviderCapabilityException} before any size matters. The branch
     * below is chosen by PROBING the module ({@code fipsDsaCanGenerate}, which
     * pins the typed refusal on its way to returning false), never by naming a
     * module version - two supported modules disagree and the contract is what
     * gets asserted.
     */
    @Test
    public void fipsDsaSizeRuleIsTheModulesOwn() throws Exception
    {
        // init() is Java-side and module-independent: the FIPS generator was
        // constructed with the FIPS 186-4 set, so these hold on both modules.
        refuses("DSA", 511);
        refuses("DSA", 512);
        refuses("DSA", 1024);
        refuses("DSA", 4096);
        refuses("DSA", 10001);
        accepts("DSA", 2048);
        accepts("DSA", 3072);

        // DH keeps the base rule on the FIPS side: the module refuses DH
        // paramgen outright whatever the size (JO_DH_PARAMGEN_SUBSTITUTED), so
        // there is nothing size-shaped to gate at init.
        accepts("DH", 512);
        accepts("DH", 1024);
        refuses("DH", 511);
        refuses("DH", 10001);
    }

    /**
     * Drive {@code init(size)} with an ARBITRARY size, rather than routing
     * through the survey's fault enum.
     *
     * <p>The enum's cells are fixed sizes chosen for the base table, and the
     * FIPS 186-4 pairs are not among them - an earlier version of this test
     * mapped 1024 onto the 1000-bit cell and had no cell at all for 2048 or
     * 3072, so it would have asserted the wrong sizes and thrown from its own
     * default arm. Naming the size here keeps the assertion and the claim the
     * same thing.
     */
    private static Observation initWith(String name, int size)
    {
        return Observer.observe(() -> {
            AlgorithmParameterGenerator g = AlgorithmParameterGenerator.getInstance(
                    name, fips);
            g.init(size);
            return null;
        });
    }

    private static void refuses(String name, int size)
    {
        Observation o = initWith(name, size);
        Assertions.assertTrue(o.isThrow(),
                "JSLFIPS " + name + " init(" + size + ") must be refused at init");
        Assertions.assertEquals(java.security.InvalidParameterException.class, o.thrown().getClass(),
                "JSLFIPS " + name + " init(" + size + "): wrong refusal type ("
                        + o.message() + ")");
    }

    private static void accepts(String name, int size)
    {
        Observation o = initWith(name, size);
        Assertions.assertFalse(o.isThrow(),
                "JSLFIPS " + name + " init(" + size + ") must be accepted at init, but it threw "
                        + (o.isThrow() ? o.thrown().getClass().getName() + " / " + o.message() : ""));
    }

    /**
     * The FIPS registered set is read live, so a module that stops serving a
     * generator is reported by NAME rather than silently shrinking the survey.
     */
    @Test
    public void fipsNameAccountingIsComplete()
    {
        TreeSet<String> live = new TreeSet<String>(names());
        Assertions.assertEquals(new TreeSet<String>(java.util.Arrays.asList("DH", "DSA")), live,
                "the JSLFIPS AlgorithmParameterGenerator primaries changed; measured against"
                        + " the module this run is configured with");
        for (String n : live)
        {
            Assertions.assertNotNull(bc.getService(
                            AlgorithmParameterGeneratorNegativePathSurveyTest.TYPE, n),
                    "no reference serves " + n + ", so it cannot be a CELL");
        }
    }
}
