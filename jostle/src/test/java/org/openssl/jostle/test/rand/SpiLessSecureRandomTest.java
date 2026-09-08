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

package org.openssl.jostle.test.rand;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.rand.DefaultRandSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-69: a caller-supplied {@link SecureRandom} with no Spi must not produce a
 * {@code NullPointerException}.
 *
 * <h2>The trigger, and why the obvious subclass does NOT reproduce it</h2>
 *
 * <p>{@code new SecureRandom() {}} does <b>not</b> trigger this. The public
 * no-arg constructor installs a real Spi — measured as {@code NativePRNG} — so
 * {@code getParameters()} returns null harmlessly. The shape that triggers it is
 * the <b>protected {@code SecureRandom(SecureRandomSpi, Provider)} constructor
 * called with nulls</b>, which leaves {@code secureRandomSpi} null so
 * {@code getParameters()} throws.
 *
 * <p>That is how BouncyCastle's {@code FixedSecureRandom} is built, and how any
 * deterministic test random tends to be built. {@link SpiLessRandom} below
 * reproduces it locally: this test must NOT depend on bc-test classes.
 *
 * <h2>Why a caller's SecureRandom is CALLER data</h2>
 *
 * <p>It arrives through a published JCA method, so a malformed one must produce
 * a typed outcome or be tolerated — never an NPE from inside the provider.
 * {@code DefaultRandSource} already tolerates "this random reports no
 * DrbgParameters", which is the path a well-formed random with null parameters
 * takes; the fix routes the Spi-less case into that same tolerated path.
 *
 * <h2>Placement</h2>
 *
 * <p>Release 8 deliberately: nothing here needs a Java 9+ API, so it runs on
 * EVERY leg. The base {@code :jostle:test} leg loads the java8 baseline, which
 * has no {@code getParameters()} call at all and is therefore the control
 * proving the baseline was never affected. The companion assertion that a real
 * {@code DrbgParameters} instantiation is still honoured cannot compile at
 * release 8 and lives in {@code src/test/java25}.
 */
public class SpiLessSecureRandomTest
{
    private static Provider jsl;

    /** A SecureRandom with a null Spi — the shape that makes getParameters() throw. */
    static final class SpiLessRandom extends SecureRandom
    {
        SpiLessRandom()
        {
            // The protected (SecureRandomSpi, Provider) constructor. Passing
            // nulls leaves secureRandomSpi null, which is the whole point.
            super(null, null);
        }

        @Override
        public void nextBytes(byte[] bytes)
        {
            java.util.Arrays.fill(bytes, (byte) 7);
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

        // WHICH COPY RAN. DefaultRandSource has a java9 override carrying the
        // getParameters() calls this test is about; the java8 baseline has
        // none. A classes directory means the baseline, a jar means the
        // override. Recorded, never asserted - so each leg's XML says which
        // copy it exercised.
        Object src = null;
        try
        {
            src = DefaultRandSource.class.getProtectionDomain().getCodeSource().getLocation();
        }
        catch (Throwable ignored)
        {
            // A null CodeSource is legal; the line below then says so.
        }
        System.out.println("[MT-69] DefaultRandSource code source=" + src);
        System.out.flush();
    }

    /**
     * The Spi-less random must be accepted everywhere it can be supplied.
     *
     * <p>Every family is driven in one test and the failures collected, so a
     * run reports the whole affected surface rather than stopping at the first
     * — the surface is the finding.
     */
    @Test
    public void spiLessSecureRandomIsAcceptedEverywhereItCanBeSupplied() throws Exception
    {
        List<String> failures = new ArrayList<String>();
        List<String> nonCompletions = new ArrayList<String>();

        check(failures, nonCompletions, "KeyPairGenerator EC (spec)", new Case()
        {
            public void run(SecureRandom r) throws Exception
            {
                KeyPairGenerator k = KeyPairGenerator.getInstance("EC", jsl);
                k.initialize(new ECGenParameterSpec("P-256"), r);
            }
        });
        check(failures, nonCompletions, "KeyPairGenerator EC (size)", new SizeCase("EC", 256));
        check(failures, nonCompletions, "KeyPairGenerator RSA", new SizeCase("RSA", 2048));
        check(failures, nonCompletions, "KeyPairGenerator DSA", new SizeCase("DSA", 2048));
        check(failures, nonCompletions, "KeyPairGenerator DH", new SizeCase("DH", 2048));
        check(failures, nonCompletions, "KeyPairGenerator Ed25519", new SizeCase("Ed25519", 255));
        check(failures, nonCompletions, "KeyPairGenerator X25519", new SizeCase("X25519", 255));

        // Reaches the SECOND site: DefaultRandSource.strengthOf, via the PQC
        // strength gate rather than via replaceWith.
        check(failures, nonCompletions, "KeyPairGenerator ML-KEM-768 (strengthOf)", new Case()
        {
            public void run(SecureRandom r) throws Exception
            {
                KeyPairGenerator k = KeyPairGenerator.getInstance("ML-KEM-768", jsl);
                k.initialize(MLKEMParameterSpec.ml_kem_768, r);
            }
        });

        // Not only KeyPairGenerator: signing takes a caller random too.
        check(failures, nonCompletions, "Signature.initSign SHA256withECDSA", new Case()
        {
            public void run(SecureRandom r) throws Exception
            {
                KeyPairGenerator k = KeyPairGenerator.getInstance("EC", jsl);
                k.initialize(new ECGenParameterSpec("P-256"));
                KeyPair kp = k.generateKeyPair();
                Signature s = Signature.getInstance("SHA256withECDSA", jsl);
                s.initSign(kp.getPrivate(), r);
                s.update(new byte[32]);
                s.sign();
            }
        });

        // NON-VACUITY, asserted before the property. `check` ignores any
        // non-NPE outcome, so a cell whose family stopped being served - or
        // whose key size this build stopped accepting - would pass while
        // testing nothing, and nine such cells would pass the property
        // assertion below with zero candidates considered. Requiring every
        // cell to run to completion makes that impossible, and the message
        // NAMES the cell and its exception rather than leaving a floor to
        // guess at.
        Assertions.assertTrue(nonCompletions.isEmpty(),
                "every cell must exercise the path; these did not run to completion, so their"
                        + " NPE check considered nothing:\n  " + join(nonCompletions));

        Assertions.assertTrue(failures.isEmpty(),
                "a caller-supplied SecureRandom with no Spi must not raise NullPointerException:\n  "
                        + join(failures));
    }

    interface Case
    {
        void run(SecureRandom r) throws Exception;
    }

    static final class SizeCase implements Case
    {
        private final String alg;
        private final int size;

        SizeCase(String alg, int size)
        {
            this.alg = alg;
            this.size = size;
        }

        public void run(SecureRandom r) throws Exception
        {
            KeyPairGenerator.getInstance(alg, jsl).initialize(size, r);
        }
    }

    /**
     * Record a failure for ANY {@code NullPointerException}, whatever its
     * message.
     *
     * <p>An unrelated refusal — a size this build will not take, a family this
     * provider does not serve — is not this defect and is ignored. But the
     * property being asserted is simply <b>no NPE reaches the caller</b>, so the
     * match must not depend on the message text.
     *
     * <p><b>An earlier version matched on the message containing
     * "secureRandomSpi" and was silently vacuous on JDK 11.</b> Helpful NPE
     * messages arrived in JDK 14; on JDK 11 the same failure carries a
     * {@code null} message, so the matcher discarded it and the test passed
     * against unfixed code on exactly the leg that runs JDK 11. Measured:
     * JDK 11 reports {@code NullPointerException: null}, JDK 17/21/25 report
     * {@code "Cannot invoke ... because this.secureRandomSpi is null"}.
     */
    private static void check(List<String> failures, List<String> nonCompletions, String what, Case c)
    {
        String outcome;
        try
        {
            c.run(new SpiLessRandom());
            outcome = "COMPLETED";
        }
        catch (Throwable t)
        {
            Throwable root = t;
            while (root.getCause() != null)
            {
                root = root.getCause();
            }
            String detail = root.getClass().getName() + ": " + root.getMessage();
            if (root instanceof NullPointerException)
            {
                failures.add(what + " -> " + detail);
                outcome = "NPE";
            }
            else
            {
                nonCompletions.add(what + " -> " + detail);
                outcome = "OTHER";
            }
        }
        // Printed for every cell so each leg's XML records what it actually
        // exercised, not merely that the test passed.
        System.out.println("[MT-69] " + outcome + " " + what);
    }

    private static String join(List<String> lines)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.size(); i++)
        {
            sb.append(i > 0 ? "\n  " : "").append(lines.get(i));
        }
        return sb.toString();
    }
}
