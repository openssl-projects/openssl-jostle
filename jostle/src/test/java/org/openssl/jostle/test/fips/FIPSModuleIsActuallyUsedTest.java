/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;

import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

/**
 * Is the FIPS module <b>actually</b> performing JSLFIPS's work?
 * <p>
 * Everything else in the FIPS suite answers this only indirectly:
 * <ul>
 *   <li><b>Absence tests</b> (Triple-DES, ChaCha20, OCB, scrypt, MD5) show the
 *       lib ctx carries {@code fips=yes} default properties, because mainline
 *       implements those and the module does not.</li>
 *   <li><b>Behavioural refusals</b> (q-less DH at derive-init, SHA-1 signing
 *       and DSA generation under {@code -pedantic}, PKCS#1 v1.5 encrypt) show
 *       the module is in the path <i>for those algorithms</i>, because mainline
 *       does not refuse them.</li>
 * </ul>
 * Neither covers a family mainline implements identically — and the bundled
 * libcrypto implements ML-KEM, ML-DSA and SLH-DSA exactly as the 3.5.x module
 * does. Before this test, every PQC test here would have passed unchanged if
 * the operations had been running in mainline's default provider.
 * <p>
 * So this asks OpenSSL directly, per algorithm:
 * {@code EVP_*_fetch} then {@code EVP_*_get0_provider} then
 * {@code OSSL_PROVIDER_get0_name} — {@code "fips"} or {@code "default"}. It is
 * the one signal that reports what OpenSSL resolved rather than what a build
 * claims.
 * <p>
 * <p><b>Scope, established by falsification rather than assumption.</b> This
 * reports on the lib ctx reachable through {@code OpenSSLFIPSNI}, so it proves
 * the module is loaded, configured {@code fips=yes}, and serving the names
 * JSLFIPS registers. It does NOT prove each algorithm SPI is bound to that same
 * library: deliberately rebinding {@code MLDSAServiceFIPSFFI} to the
 * process-global {@code loaderLookup} left every test here green, because the
 * probe runs through a different, correctly-bound class. That invariant is
 * enforced structurally by {@link FIPSLibraryLookupParityTest} instead.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSModuleIsActuallyUsedTest
{
    /** OpenSSL's name for the FIPS module provider. */
    private static final String FIPS_PROVIDER = "fips";

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    /**
     * Every algorithm JSLFIPS serves is implemented by the {@code fips}
     * provider, across every operation type.
     * <p>
     * Derived from the provider's own registered surface rather than a fixed
     * list, so a family added later is covered without touching this test —
     * which is the whole point, since the families most at risk are the ones
     * mainline also implements.
     */
    @Test
    public void everyServedAlgorithmIsImplementedByTheFipsModule()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();
        List<String> wrong = new ArrayList<>();
        int checked = 0;

        for (Provider.Service s : provider.getServices())
        {
            int opType = opTypeFor(s.getType());
            if (opType < 0)
            {
                continue; // no EVP fetch behind this JCE type
            }
            String alg = s.getAlgorithm();
            String impl = FIPSNISelector.OpenSSLFIPSNI.implementingProvider(opType, alg);
            if (impl == null)
            {
                // Registered under a JCE name OpenSSL does not know by that
                // spelling (an OID alias, a composite transformation, a name
                // the SPI maps before fetching). Not evidence of anything.
                continue;
            }
            checked++;
            if (!FIPS_PROVIDER.equals(impl))
            {
                wrong.add(s.getType() + "." + alg + " -> implemented by \"" + impl + "\"");
            }
        }

        Assertions.assertTrue(checked > 20,
                "only " + checked + " algorithms could be resolved by name — this test would "
                        + "pass vacuously; the probe or the name mapping is broken");

        Assertions.assertTrue(wrong.isEmpty(),
                "JSLFIPS serves algorithms NOT implemented by the FIPS module ("
                        + FIPSNISelector.OpenSSLFIPSNI.moduleVersion() + "):\n  "
                        + String.join("\n  ", wrong)
                        + "\nAn interface library bound to the wrong OSSL_LIB_CTX answers "
                        + "\"default\" here while every functional test still passes.");
    }

    /**
     * PQC specifically, named rather than swept.
     * <p>
     * These are the families where the sweep above is the ONLY evidence: the
     * bundled mainline libcrypto implements all three, so no absence test and
     * no behavioural refusal can distinguish module from mainline. Calling them
     * out separately means a future change that drops them from the sweep still
     * fails here.
     */
    @Test
    public void pqcIsImplementedByTheFipsModuleWhenServed()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        for (String alg : new String[]{"ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128S"})
        {
            boolean registered = provider.getService("KeyPairGenerator", alg) != null;
            String impl = FIPSNISelector.OpenSSLFIPSNI
                    .implementingProvider(OpenSSLFIPSNI.OP_KEYMGMT, alg);

            if (!registered)
            {
                Assertions.assertNull(impl,
                        alg + " is unregistered but the FIPS lib ctx resolves it to \""
                                + impl + "\" — a working algorithm was dropped from callers");
                continue;
            }
            Assertions.assertEquals(FIPS_PROVIDER, impl,
                    alg + " is served by JSLFIPS but implemented by \"" + impl
                            + "\" — mainline implements PQC identically, so this is the only "
                            + "check that can catch it");
        }
    }

    /**
     * The probe reports a real answer, not a constant.
     * <p>
     * Without this the two tests above would pass against a stub that always
     * returned "fips". An algorithm mainline implements and the module does not
     * must come back null — proving the probe is reading the FIPS lib ctx and
     * can say something other than the answer we want.
     */
    @Test
    public void probeReportsAbsenceForAlgorithmsTheModuleLacks()
    {
        FIPSTestUtil.assumeFipsProvider();

        // ChaCha20 is in every mainline build and in no FIPS module: its
        // implementation carries fips=no, which the lib ctx's fips=yes default
        // query excludes.
        Assertions.assertNull(
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(
                        OpenSSLFIPSNI.OP_CIPHER, "ChaCha20"),
                "ChaCha20 resolved in the FIPS lib ctx — the probe is not reading a "
                        + "fips=yes context, so \"fips\" answers elsewhere prove nothing");

        // And a positive control in the same breath, so a probe that answered
        // null for everything could not pass either.
        Assertions.assertEquals(FIPS_PROVIDER,
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(
                        OpenSSLFIPSNI.OP_MD, "SHA-256"),
                "SHA-256 must resolve to the FIPS module");
    }

    /** The {@code OP_*} constant for a JCE service type, or -1 if none applies. */
    private static int opTypeFor(String jceType)
    {
        switch (jceType)
        {
            case "MessageDigest":
                return OpenSSLFIPSNI.OP_MD;
            case "Mac":
                return OpenSSLFIPSNI.OP_MAC;
            case "KeyFactory":
            case "KeyPairGenerator":
                return OpenSSLFIPSNI.OP_KEYMGMT;
            case "KeyAgreement":
                return OpenSSLFIPSNI.OP_KEYEXCH;
            case "Signature":
                return OpenSSLFIPSNI.OP_SIGNATURE;
            default:
                // Cipher / KeyGenerator / SecretKeyFactory / AlgorithmParameters
                // and friends are registered under JCE transformation names the
                // SPI decomposes before fetching, so a by-name fetch is not
                // meaningful for them.
                return -1;
        }
    }
}
