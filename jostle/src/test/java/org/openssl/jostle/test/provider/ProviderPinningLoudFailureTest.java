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
     * The unbound arm: an SPI constructed outside any provider has no provider
     * to compute its KDF digest, and must say so rather than fall through to
     * whatever JCA has installed.
     *
     * <p>Before MT-16 this arm did not exist — the no-argument constructor
     * hard-pinned the name {@code "JSL"}, so a directly-constructed SPI
     * quietly borrowed whatever instance that name resolved to. Binding is by
     * reference now, and an SPI with no provider has no identity to borrow.
     */
    @Test
    public void ktsWrap_unboundSpi_failsAtTheDigestPinRatherThanFallingThrough() throws Exception
    {
        // Generated through the SPI directly, NOT through the registered
        // provider, so both sides live in the unbound realm; a key from the
        // registered provider would be refused by MT-14 instance binding
        // before the wrap path this test exists to drive was ever reached.
        KeyPair kp = new org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator(
                "ML-KEM-768").generateKeyPair();

        Probe unbound = new Probe();
        unbound.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec(), new SecureRandom());

        Exception e = Assertions.assertThrows(Exception.class,
                () -> unbound.wrap(new SecretKeySpec(new byte[32], "AES")),
                "wrapping with no provider must fail, not fall through to whatever JCA "
                        + "has installed");
        String msg = rootMessage(e);
        // Must fail at the DIGEST pin specifically, not merely somewhere. The
        // AES key wrap is pinned the same way and fails the same way, so
        // "it threw and mentioned a provider" would pass with the digest pin
        // gone — this is the assertion that separates the two.
        Assertions.assertTrue(msg.contains("SHA-256 KDF digest cannot be computed by it"),
                "must fail at the KDF DIGEST pin naming the digest; got: " + msg);
        Assertions.assertTrue(msg.contains("constructed outside any provider"),
                "must name the cause as having no provider; got: " + msg);
    }

    /**
     * The bound-but-incapable arm, driven end to end through the real JCE
     * surface: a JSL instance with SHA-256 removed must fail the wrap naming
     * itself, rather than borrow the digest from another installed provider.
     *
     * <p>This is the arm a NAME pin could not express. With the pin on a
     * name, "my provider" meant whatever the name resolved to at call time;
     * with it on the instance, an instance that cannot serve the digest is a
     * hard failure even though the installed provider of the same NAME can.
     */
    @Test
    public void ktsWrap_ownInstanceWithoutTheDigest_failsNamingItRatherThanBorrowing() throws Exception
    {
        Provider digestless = new StrippedJostleProvider("MessageDigest", "SHA-256");
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME)
                        .getService("MessageDigest", "SHA-256"),
                "the INSTALLED JSL must still serve SHA-256 — otherwise this test proves "
                        + "nothing about instance identity, only about absence");

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", digestless).generateKeyPair();
        Cipher c = Cipher.getInstance("ML-KEM", digestless);
        c.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec(), new SecureRandom());

        Exception e = Assertions.assertThrows(Exception.class,
                () -> c.wrap(new SecretKeySpec(new byte[32], "AES")));
        String msg = rootMessage(e);
        Assertions.assertTrue(msg.contains("does not serve SHA-256"),
                "must name the digest it cannot serve; got: " + msg);
        Assertions.assertTrue(msg.contains("KDF digest cannot be computed by it"),
                "must fail at the KDF DIGEST pin; got: " + msg);
    }

    /**
     * The same, one lookup later: the AES key wrap is pinned to the instance
     * too, and an instance that cannot serve it fails rather than borrowing.
     * Separate from the digest arm on purpose — with only one of the two
     * tests, a regression that unpinned the other would go unseen.
     */
    @Test
    public void ktsWrap_ownInstanceWithoutTheKeyWrap_failsNamingItRatherThanBorrowing() throws Exception
    {
        // id-aes256-wrap: the KEK is 256-bit, so this is the OID the wrap
        // resolves. Removing it leaves the digest intact, so a failure here
        // can only be the key-wrap pin.
        Provider kwless = new StrippedJostleProvider("Cipher", "2.16.840.1.101.3.4.1.45");

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", kwless).generateKeyPair();
        Cipher c = Cipher.getInstance("ML-KEM", kwless);
        c.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec(), new SecureRandom());

        Exception e = Assertions.assertThrows(Exception.class,
                () -> c.wrap(new SecretKeySpec(new byte[32], "AES")));
        String msg = rootMessage(e);
        Assertions.assertTrue(msg.contains("does not serve the AES key wrap"),
                "must fail at the AES KEY WRAP pin; got: " + msg);
        Assertions.assertTrue(msg.contains("2.16.840.1.101.3.4.1.45"),
                "must name the key-wrap OID it cannot serve; got: " + msg);
    }

    /**
     * Positive control for all three arms above. Without it they would pass
     * against a KTS cipher that refused every provider, including a capable
     * one.
     */
    @Test
    public void ktsWrap_ownInstanceThatServesEverything_wraps() throws Exception
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", jsl).generateKeyPair();
        Cipher c = Cipher.getInstance("ML-KEM", jsl);
        c.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec(), new SecureRandom());

        // wrap() THROWS on failure, so asserting non-null on its result asserts
        // nothing: a wrapping that produced the wrong bytes would pass. The
        // property this test is named for is that the instance WRAPS, and the
        // only thing that demonstrates it is recovering the key again.
        byte[] cek = new byte[32];
        new SecureRandom().nextBytes(cek);
        byte[] wrapped = c.wrap(new SecretKeySpec(cek, "AES"));

        Cipher unwrapper = Cipher.getInstance("ML-KEM", jsl);
        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsSpec(), new SecureRandom());
        Key recovered = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(cek, recovered.getEncoded(),
                "the wrapped CEK did not come back — wrap produced the wrong bytes");
    }

    /** A 256-bit KEK derived by KDF3/SHA-256 — what all four arms drive. */
    private static KTSParameterSpec ktsSpec()
    {
        return new KTSParameterSpec.Builder("AES", 256)
                .withKdfAlgorithm(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_kdf_kdf3,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                .build();
    }

    /** Exposes the protected SPI surface so the real wrap path can be driven. */
    private static final class Probe
            extends MLKEMKTSCipherSpi
    {
        Probe()
        {
            super(new MLKEMKeyFactorySpi(), NISelector.SpecNI);
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
