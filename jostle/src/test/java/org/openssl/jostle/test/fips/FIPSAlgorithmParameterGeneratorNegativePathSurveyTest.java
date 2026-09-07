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
import org.openssl.jostle.test.parity.SurveyReport;
import org.openssl.jostle.test.parity.ThreeWay;

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
        report.assertMeasured(18, names.size(), 0);
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
