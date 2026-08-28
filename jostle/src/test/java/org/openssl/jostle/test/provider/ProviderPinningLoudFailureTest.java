/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.kdf.KeyAgreementKDF;
import org.openssl.jostle.jcajce.provider.wrap.UnwrappedKeys;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKTSCipherSpi;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Pins MT-5's loud-failure contract: when a provider-pinned digest cannot be
 * resolved from the SPI's OWN provider, the failure is typed and names the
 * provider — it never falls through to whatever else JCA has installed.
 *
 * <p><b>Why this needs a test at all.</b> The branch is near-unreachable in a
 * healthy build: the provider name is sourced from construction, and both
 * Jostle providers register the full digest set, so "my own provider does not
 * serve my digest" means the build is broken. That is precisely the kind of
 * claim that rots unnoticed — the repo's rule is that a claim gets pinned, and
 * a fallback nobody exercises is a fallback nobody knows still works.
 *
 * <p>It is also the half the structural lint cannot reach.
 * {@link ProviderPinningParityTest} proves every call site NAMES a provider;
 * only this proves that naming an unusable one FAILS rather than silently
 * degrading. A silent JSL fall-through is exactly the shape that hid the
 * original defect.
 *
 * <p>Pure Java, no FIPS module needed: an uninstalled provider name behaves
 * identically under both providers, which is the contract.
 */
public class ProviderPinningLoudFailureTest
{
    /** A provider name that is guaranteed not to be installed. */
    private static final String ABSENT = "NoSuchProviderJSL";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        Assertions.assertNull(Security.getProvider(ABSENT),
                "the test's sentinel provider name must not actually be installed");
    }

    // -----------------------------------------------------------------
    // KeyAgreementKDF — the X9.42 / X9.63 derivation
    // -----------------------------------------------------------------

    @Test
    public void x942_absentProvider_failsTypedNamingTheProvider()
    {
        NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> KeyAgreementKDF.x942(ABSENT, "SHA-256", new byte[32],
                        "2.16.840.1.101.3.4.1.5", 16, null));
        Assertions.assertEquals(
                "provider " + ABSENT + " is not installed, so the SHA-256 KDF digest "
                        + "cannot be computed by it", e.getMessage());
    }

    @Test
    public void x963_absentProvider_failsTypedNamingTheProvider()
    {
        NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> KeyAgreementKDF.x963(ABSENT, "SHA-256", new byte[32], 16, null));
        Assertions.assertEquals(
                "provider " + ABSENT + " is not installed, so the SHA-256 KDF digest "
                        + "cannot be computed by it", e.getMessage());
    }

    /**
     * The null arm. A caller that forgets to thread the provider name must be
     * told to supply it, not silently fall back to the JCA search order — the
     * fallback being the defect MT-5 removed.
     */
    @Test
    public void nullProviderName_failsTypedTellingTheCallerToSupplyIt()
    {
        for (String which : new String[]{"x942", "x963"})
        {
            NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> {
                        if ("x942".equals(which))
                        {
                            KeyAgreementKDF.x942(null, "SHA-256", new byte[32],
                                    "2.16.840.1.101.3.4.1.5", 16, null);
                        }
                        else
                        {
                            KeyAgreementKDF.x963(null, "SHA-256", new byte[32], 16, null);
                        }
                    }, which);
            Assertions.assertEquals(
                    "no provider named for the SHA-256 KDF digest; the calling SPI must supply "
                            + "the provider it belongs to so the KDF is not computed outside it",
                    e.getMessage(), which);
        }
    }

    /**
     * Positive control. Without it the three assertions above would pass
     * against a KDF that rejected every provider, including the right one.
     */
    @Test
    public void ownProvider_resolvesAndDerives() throws Exception
    {
        byte[] kek = KeyAgreementKDF.x942(JostleProvider.PROVIDER_NAME, "SHA-256",
                new byte[32], "2.16.840.1.101.3.4.1.5", 16, null);
        Assertions.assertEquals(16, kek.length);
        Assertions.assertFalse(allZero(kek), "a derived KEK of all zeros means nothing derived");
    }

    // -----------------------------------------------------------------
    // The KTS cipher — the same contract one layer up, driven end to end
    // -----------------------------------------------------------------

    /**
     * Drives the real wrap path with a bogus provider name, so the pin is
     * pinned where it actually ships rather than only in the KDF helper.
     */
    @Test
    public void ktsWrap_absentProvider_failsRatherThanFallingThrough() throws Exception
    {
        // Generated through the SPI directly, NOT through the registered
        // provider. Probe below is likewise a directly-constructed SPI, so
        // both sides live in the unbound realm; a key from the registered
        // provider would be refused by MT-14 instance binding before the wrap
        // path this test exists to drive was ever reached.
        KeyPair kp = new org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator(
                "ML-KEM-768").generateKeyPair();

        KTSParameterSpec kts = new KTSParameterSpec.Builder("AES", 256)
                .withKdfAlgorithm(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_kdf_kdf3,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                .build();

        Probe bad = new Probe(ABSENT);
        bad.init(Cipher.WRAP_MODE, kp.getPublic(), kts, new SecureRandom());

        Exception e = Assertions.assertThrows(Exception.class,
                () -> bad.wrap(new SecretKeySpec(new byte[32], "AES")),
                "wrapping with an unusable provider name must fail, not fall through to "
                        + "whatever JCA has installed");
        // Must fail at the DIGEST pin specifically, not merely somewhere.
        //
        // This assertion was too loose on first writing and the falsification
        // caught it: with the digest silently falling through to SUN, the wrap
        // still failed — at the AES key-wrap pin — so "it failed and named the
        // provider" passed while the digest pin was gone. Requiring the
        // digest-specific message is what distinguishes the two pins.
        String msg = rootMessage(e);
        Assertions.assertTrue(msg.contains(ABSENT), "must name the provider; got: " + msg);
        Assertions.assertTrue(msg.contains("KDF digest cannot be computed"),
                "must fail at the KDF DIGEST pin, not merely at some later pin — a silent "
                        + "digest fall-through would still fail here at the AES key wrap and "
                        + "look identical without this check; got: " + msg);

        // Control: the same SPI with its own provider name wraps successfully,
        // so the failure above is the provider name and nothing else.
        Probe good = new Probe(JostleProvider.PROVIDER_NAME);
        good.init(Cipher.WRAP_MODE, kp.getPublic(), kts, new SecureRandom());
        Assertions.assertNotNull(good.wrap(new SecretKeySpec(new byte[32], "AES")));
    }

    /** Exposes the protected SPI surface so the real wrap path can be driven. */
    private static final class Probe extends MLKEMKTSCipherSpi
    {
        Probe(String providerName)
        {
            super(new MLKEMKeyFactorySpi(), NISelector.SpecNI, providerName);
        }

        void init(int mode, Key key, AlgorithmParameterSpec spec, SecureRandom random)
                throws Exception
        {
            engineInit(mode, key, spec, random);
        }

        byte[] wrap(Key key) throws Exception
        {
            return engineWrap(key);
        }
    }

    private static String rootMessage(Throwable t)
    {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause())
        {
            sb.append(c.getMessage()).append(' ');
        }
        return sb.toString();
    }

    private static boolean allZero(byte[] b)
    {
        for (byte x : b)
        {
            if (x != 0)
            {
                return false;
            }
        }
        return true;
    }

    // -----------------------------------------------------------------
    // UnwrappedKeys — MT-10's unbound-SPI arm
    // -----------------------------------------------------------------

    /**
     * An SPI constructed outside any provider has nothing to bind an
     * unwrapped asymmetric key to, and must say so rather than reach for JCA
     * order — the same loud-failure contract as MT-5's digest pins above, one
     * work item later.
     *
     * <p>Pinned here at the helper rather than end to end because
     * {@code engineUnwrap} is {@code protected} and every provider-mediated
     * route is bound by construction, so there is no legal JCE call that
     * reaches this arm. That makes it exactly the kind of near-unreachable
     * branch this class exists for: unexercised, and therefore not known to
     * still work.
     */
    @Test
    public void unwrappedKeys_unboundSpi_failsTypedNamingTheCause()
    {
        NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> UnwrappedKeys.keyFactory(null, "EC"));
        Assertions.assertEquals(
                "cannot reconstruct an unwrapped EC key: this cipher was constructed outside "
                        + "any provider, so there is no provider instance to bind the key to. "
                        + "Obtain the Cipher from a Jostle provider rather than constructing "
                        + "the SPI directly.",
                e.getMessage());
    }

    /**
     * And a provider that IS named but serves no such KeyFactory fails naming
     * both, rather than silently resolving elsewhere. The base
     * {@code UnwrappedKeyBindingTest} covers this through the JCE surface;
     * this pins the helper's own message, which is what that test matches on.
     */
    @Test
    public void unwrappedKeys_providerWithoutTheKeyFactory_namesProviderAndAlgorithm()
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> UnwrappedKeys.keyFactory(jsl, "NoSuchKeyAlgorithm"));
        Assertions.assertTrue(
                e.getMessage().startsWith(
                        "provider JSL serves no KeyFactory for NoSuchKeyAlgorithm"),
                "got: " + e.getMessage());
    }
}
