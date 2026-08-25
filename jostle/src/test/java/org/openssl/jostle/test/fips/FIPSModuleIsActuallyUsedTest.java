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
     * EdDSA specifically, named rather than swept — same reasoning as
     * {@link #pqcIsImplementedByTheFipsModuleWhenServed}.
     * <p>
     * The bundled mainline libcrypto implements Ed25519 and Ed448 exactly as
     * the 3.5.x module does, so every signature, encoding and BC-agreement
     * test passes identically whether the work happened in the module or in
     * mainline's default provider. Asking which provider implements it is the
     * only check that can tell them apart.
     * <p>
     * Both branches are asserted: registered ⇒ the module implements it;
     * unregistered ⇒ the module must genuinely not resolve it, so a working
     * algorithm cannot be quietly dropped from callers.
     */
    @Test
    public void edIsImplementedByTheFipsModuleWhenServed()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        for (String alg : new String[]{"ED25519", "ED448"})
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
                            + "\" — mainline implements EdDSA identically, so this is the only "
                            + "check that can catch it");
        }

        // The signature side separately: a keymgmt that resolves to the module
        // does not prove the SIGNATURE implementation does, and the Ed family
        // is registered per signature name.
        for (String alg : new String[]{"ED25519", "ED25519PH", "ED448", "ED448PH", "ED25519CTX"})
        {
            boolean registered = provider.getService("Signature", alg) != null;
            String impl = FIPSNISelector.OpenSSLFIPSNI
                    .implementingProvider(OpenSSLFIPSNI.OP_SIGNATURE, alg);

            if (!registered)
            {
                Assertions.assertNull(impl,
                        "Signature." + alg + " is unregistered but the FIPS lib ctx resolves it to \""
                                + impl + "\" — a working algorithm was dropped from callers");
                continue;
            }
            Assertions.assertEquals(FIPS_PROVIDER, impl,
                    "Signature." + alg + " is served by JSLFIPS but implemented by \"" + impl + "\"");
        }
    }

    /**
     * The cipher-backed MACs specifically, named rather than swept.
     * <p>
     * The sweep above probes each service under its JCE name, and for these two
     * that name is not the EVP one: JSLFIPS registers {@code Mac.AESCMAC} and
     * {@code Mac.AESGMAC} while OpenSSL knows them as {@code CMAC} and
     * {@code GMAC} (the AES variant follows the key length, so it is not part
     * of the fetched name). {@code implementingProvider} therefore answers null
     * for both and the sweep skips them — silently, and with no evidence either
     * way.
     * <p>
     * That blind spot matters most for GMAC, where mainline 3.6.2, FIPS 3.1.2
     * and FIPS 3.5.7 produce byte-identical tags for identical inputs
     * (measured, {@code fips-c-review/probes/gmac_probe.c}), so no agreement,
     * negative or chunking test can tell the module from mainline. Asking which
     * provider implements it is the only check that can.
     */
    @Test
    public void cipherBackedMacsAreImplementedByTheFipsModule()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        // JCE registration name -> the name OpenSSL fetches it under.
        // KMAC is here for the same reason, and needs it more: mainline
        // implements it identically to both modules (byte-identical tags AND
        // matching SP 800-185 vectors on all four measured builds), so no
        // agreement, KAT, negative or chunking test can tell module from
        // mainline. OpenSSL happens to accept the JCE spelling as an alias, so
        // the sweep above may cover it - naming it here means a future name
        // mapping that broke that alias still fails rather than silently
        // dropping KMAC into the skipped-because-null bucket.
        String[][] macs = {{"AESCMAC", "CMAC"}, {"AESGMAC", "GMAC"},
                {"KMAC128", "KMAC-128"}, {"KMAC256", "KMAC-256"}};

        for (String[] mac : macs)
        {
            boolean registered = provider.getService("Mac", mac[0]) != null;
            String impl = FIPSNISelector.OpenSSLFIPSNI
                    .implementingProvider(OpenSSLFIPSNI.OP_MAC, mac[1]);

            if (!registered)
            {
                Assertions.assertNull(impl,
                        "Mac." + mac[0] + " is unregistered but the FIPS lib ctx resolves "
                                + mac[1] + " to \"" + impl
                                + "\" — a working algorithm was dropped from callers");
                continue;
            }
            Assertions.assertEquals(FIPS_PROVIDER, impl,
                    "Mac." + mac[0] + " is served by JSLFIPS but " + mac[1]
                            + " is implemented by \"" + impl + "\"");
        }
    }

    /**
     * RSA-KEM specifically. The sweep resolves {@code Cipher.RSA-KTS-KEM-KWS}
     * to nothing - OpenSSL has no cipher of that name; the mechanism is an
     * {@code EVP_PKEY} KEM operation on an RSA key - so the family is invisible
     * to it. Mainline implements RSASVE identically to both modules, so this
     * probe is the only thing that can tell them apart.
     */
    @Test
    public void rsaKemIsImplementedByTheFipsModule()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        Assertions.assertNotNull(provider.getService("Cipher", "RSA-KTS-KEM-KWS"),
                "RSA-KEM is ungated and must always be registered");
        Assertions.assertEquals(FIPS_PROVIDER,
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_KEYMGMT, "RSA"),
                "the RSA keymgmt behind RSA-KEM must be the module's");
    }

    /**
     * AES CBC-CTS specifically, named rather than swept.
     * <p>
     * Same blind spot as Triple-DES: the sweep probes each service under its
     * JCE name, and {@code AES/CTS/NoPadding} is not the EVP one — OpenSSL
     * knows {@code AES-128-CBC-CTS} and friends, with the key width part of
     * the fetched name. {@code implementingProvider} answers null for the JCE
     * spelling and the sweep skips it silently. Mainline implements CBC-CTS
     * identically to both modules, so no agreement or chunking test can tell
     * them apart.
     * <p>
     * Unlike Triple-DES this family is NOT capability-gated — all three widths
     * fetch on every supported module and configuration — so the unregistered
     * branch is a failure rather than a legitimate absence.
     */
    @Test
    public void aesCbcCtsIsImplementedByTheFipsModule()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        Assertions.assertNotNull(provider.getService("Cipher", "AES/CTS/NoPadding"),
                "AES/CTS/NoPadding is ungated and must always be registered");

        for (String evpName : new String[]{"AES-128-CBC-CTS", "AES-192-CBC-CTS", "AES-256-CBC-CTS"})
        {
            Assertions.assertEquals(FIPS_PROVIDER,
                    FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_CIPHER, evpName),
                    evpName + " must be implemented by the FIPS module — mainline implements "
                            + "CBC-CTS identically, so this is the only check that can catch it");
        }
    }

    /**
     * Triple-DES specifically, named rather than swept.
     * <p>
     * The sweep probes each service under its JCE name, and {@code DESede} is
     * not the EVP one — OpenSSL knows {@code DES-EDE3-CBC} / {@code DES-EDE3-ECB},
     * with the mode part of the fetched name. {@code implementingProvider}
     * therefore answers null for {@code DESede} and the sweep skips it,
     * silently and with no evidence either way. That matters here because
     * mainline libcrypto implements Triple-DES identically to the 3.5.x module,
     * so no agreement, chunking or negative test can tell them apart.
     * <p>
     * Both branches are asserted, and note the registration check and the probe
     * deliberately use DIFFERENT names: {@code Cipher.DESede} is what JSLFIPS
     * registers, {@code DES-EDE3-CBC} is what OpenSSL resolves.
     */
    @Test
    public void tripleDesIsImplementedByTheFipsModuleWhenServed()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        boolean registered = provider.getService("Cipher", "DESede") != null;

        for (String evpName : new String[]{"DES-EDE3-CBC", "DES-EDE3-ECB"})
        {
            String impl = FIPSNISelector.OpenSSLFIPSNI
                    .implementingProvider(OpenSSLFIPSNI.OP_CIPHER, evpName);

            if (!registered)
            {
                Assertions.assertNull(impl,
                        "Cipher.DESede is unregistered but the FIPS lib ctx resolves "
                                + evpName + " to \"" + impl
                                + "\" — a working algorithm was dropped from callers");
                continue;
            }
            Assertions.assertEquals(FIPS_PROVIDER, impl,
                    "Cipher.DESede is served by JSLFIPS but " + evpName
                            + " is implemented by \"" + impl
                            + "\" — mainline implements Triple-DES identically, so this is "
                            + "the only check that can catch it");
        }
    }

    /**
     * The KDFs behind the {@code SecretKeyFactory} surface are implemented by
     * the FIPS module.
     * <p>
     * {@link #opTypeFor} deliberately returns -1 for {@code SecretKeyFactory},
     * because the JCE registration name ({@code KBKDF-HMAC-SHA256}) is not the
     * name OpenSSL fetches ({@code KBKDF}) — so the sweep above skips the whole
     * family. That leaves the KDFs in exactly the blind spot the class exists
     * to close: mainline implements KBKDF, SSKDF and SSHKDF identically to both
     * supported modules (measured, {@code fips-c-review/probes/kdf_probe.c} —
     * every KAT and every random-input agreement matches on all four builds),
     * so no agreement, KAT or negative test can tell module from mainline.
     * Asking which provider implements them is the only check that can.
     */
    @Test
    public void secretKeyFactoryKdfsAreImplementedByTheFipsModule()
    {
        Provider provider = FIPSTestUtil.assumeFipsProvider();

        // A registered JCE name -> the EVP_KDF name behind it.
        String[][] kdfs = {
                {"PBKDF2", "PBKDF2"},
                {"HKDF-SHA256", "HKDF"},
                {"KBKDF-HMAC-SHA256", "KBKDF"},
                {"KBKDF-CMAC-AES128", "KBKDF"},
                {"SSKDF-SHA256", "SSKDF"},
                {"SSHKDF-SHA256", "SSHKDF"},
        };

        for (String[] kdf : kdfs)
        {
            boolean registered = provider.getService("SecretKeyFactory", kdf[0]) != null;
            String impl = FIPSNISelector.OpenSSLFIPSNI
                    .implementingProvider(OpenSSLFIPSNI.OP_KDF, kdf[1]);

            if (!registered)
            {
                Assertions.assertNull(impl,
                        "SecretKeyFactory." + kdf[0] + " is unregistered but the FIPS lib ctx "
                                + "resolves " + kdf[1] + " to \"" + impl
                                + "\" — a working algorithm was dropped from callers");
                continue;
            }
            Assertions.assertEquals(FIPS_PROVIDER, impl,
                    "SecretKeyFactory." + kdf[0] + " is served by JSLFIPS but " + kdf[1]
                            + " is implemented by \"" + impl + "\"");
        }

        // Control in the same test: a KDF no FIPS module carries must come back
        // null, so a probe stuck on "fips" cannot pass this.
        Assertions.assertNull(
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_KDF, "SCRYPT"),
                "SCRYPT resolved in the FIPS lib ctx — the KDF probe is not reading a "
                        + "fips=yes context, so its \"fips\" answers prove nothing");
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
