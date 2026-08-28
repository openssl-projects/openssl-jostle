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
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * MT-10, FIPS half: a key produced by a JSLFIPS {@code Cipher.unwrap} is
 * resident in the FIPS module.
 *
 * <p>Not a duplicate of {@code UnwrappedKeyBindingTest}. That one drives
 * {@code libinterface_{jni,ffi}} and the base lib ctx; this drives
 * {@code libinterface_fips_{jni,ffi}} and the module's. Neither substitutes
 * for the other, and this half is the one that carries the boundary question:
 * before MT-10 a JSLFIPS unwrap called {@code KeyFactory.getInstance(alg)}
 * with no provider, so the key it returned was made by SUN and the FIPS
 * module never saw it. No functional test could tell — a SUN EC key signs the
 * bytes the module would.
 *
 * <p>So the assertion here is not only that the key is bound to the JSLFIPS
 * instance but that OpenSSL reports the {@code "fips"} provider as the one
 * serving it ({@code SpecNI.getKeyProvider}, the accessor MT-14 added).
 * {@code ownKeysAreServedByTheModule} is the control proving that accessor can
 * answer something other than {@code "fips"}.
 */
public class FIPSUnwrappedKeyBindingTest
{
    /**
     * The unwrapping SPIs JSLFIPS registers. No PKCS#1 v1.5 Cipher: JSLFIPS
     * does not register one (see the scope note in native-code.md), so it has
     * no unwrap surface to cover.
     */
    private static final String[] TRANSFORMS = {"AESWrapPad", "RSA/ECB/OAEPPadding"};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static Provider fips;
    private static KeyPair rsaKek;
    private static SecretKey aesKek;

    @BeforeAll
    static void before() throws Exception
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", fips);
        kpg.initialize(2048, RANDOM);
        rsaKek = kpg.generateKeyPair();

        KeyGenerator kg = KeyGenerator.getInstance("AES", fips);
        kg.init(256, RANDOM);
        aesKek = kg.generateKey();
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static Cipher wrapper(String transform) throws Exception
    {
        Cipher c = Cipher.getInstance(transform, fips);
        if (transform.startsWith("RSA"))
        {
            c.init(Cipher.WRAP_MODE, rsaKek.getPublic(), RANDOM);
        }
        else
        {
            c.init(Cipher.WRAP_MODE, aesKek, RANDOM);
        }
        return c;
    }

    private static Cipher unwrapper(String transform) throws Exception
    {
        Cipher c = Cipher.getInstance(transform, fips);
        if (transform.startsWith("RSA"))
        {
            c.init(Cipher.UNWRAP_MODE, rsaKek.getPrivate(), RANDOM);
        }
        else
        {
            c.init(Cipher.UNWRAP_MODE, aesKek, RANDOM);
        }
        return c;
    }

    /** A peer's EC P-256 pair, from the JVM default provider. */
    private static KeyPair payload() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256, RANDOM);
        return kpg.generateKeyPair();
    }

    private static Provider boundTo(Key key)
    {
        Assertions.assertTrue(key instanceof OSSLKey,
                "unwrap returned a " + key.getClass().getName() + ", not a Jostle key — it was "
                        + "reconstructed by some other provider");
        return ((OSSLKey) key).getSpec().getProviderInstance();
    }

    /** Which OSSL_PROVIDER owns this key's keymgmt: "fips" or "default". */
    private static String servedBy(Key key)
    {
        PKEYKeySpec spec = ((OSSLKey) key).getSpec();
        return spec.getSpecNI().getKeyProvider(spec.getReference());
    }

    // -----------------------------------------------------------------
    // control
    // -----------------------------------------------------------------

    /**
     * Control for {@link #servedBy}: it must be able to answer something other
     * than {@code "fips"}, or a stub returning that constant would pass every
     * assertion below.
     */
    @Test
    public void ownKeysAreServedByTheModuleAndJslKeysAreNot() throws Exception
    {
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        KeyPair mine = KeyPairGenerator.getInstance("EC", fips).generateKeyPair();
        KeyPair theirs = KeyPairGenerator.getInstance("EC", jsl).generateKeyPair();

        Assertions.assertEquals("fips", servedBy(mine.getPublic()));
        Assertions.assertEquals("default", servedBy(theirs.getPublic()));
    }

    // -----------------------------------------------------------------
    // the contract
    // -----------------------------------------------------------------

    @Test
    public void unwrappedPublicKeyIsResidentInTheModule() throws Exception
    {
        for (String t : TRANSFORMS)
        {
            KeyPair kp = payload();
            byte[] wrapped = wrapper(t).wrap(kp.getPublic());
            Key back = unwrapper(t).unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);

            Assertions.assertSame(fips, boundTo(back),
                    t + ": an unwrapped public key must be bound to the JSLFIPS instance");
            Assertions.assertEquals("fips", servedBy(back),
                    t + ": the key a JSLFIPS unwrap returns must be served by the FIPS module, "
                            + "not by mainline");
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(), back.getEncoded(),
                    t + ": the unwrapped key must still be the key that was wrapped");
        }
    }

    @Test
    public void unwrappedPrivateKeyIsResidentAndImmediatelyUsable() throws Exception
    {
        for (String t : TRANSFORMS)
        {
            KeyPair kp = payload();
            byte[] wrapped = wrapper(t).wrap(kp.getPrivate());
            Key back = unwrapper(t).unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);

            Assertions.assertSame(fips, boundTo(back),
                    t + ": an unwrapped private key must be bound to the JSLFIPS instance");
            Assertions.assertEquals("fips", servedBy(back),
                    t + ": a private key a JSLFIPS unwrap returns must live in the module");

            //
            // Before MT-10 this line threw InvalidKeyException — the key came
            // from SUN, and JSLFIPS refuses a foreign key object (MT-14).
            //
            byte[] msg = new byte[1 + RANDOM.nextInt(200)];
            RANDOM.nextBytes(msg);

            Signature signer = Signature.getInstance("SHA256withECDSA", fips);
            signer.initSign((java.security.PrivateKey) back, RANDOM);
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withECDSA", fips);
            verifier.initVerify(KeyFactory.getInstance("EC", fips)
                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig),
                    t + ": the unwrapped private key must be the one that was wrapped");

            msg[RANDOM.nextInt(msg.length)] ^= (byte) 0x01;
            Signature tampered = Signature.getInstance("SHA256withECDSA", fips);
            tampered.initVerify(KeyFactory.getInstance("EC", fips)
                    .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
            tampered.update(msg);
            Assertions.assertFalse(tampered.verify(sig),
                    t + ": a tampered message must not verify");
        }
    }

    @Test
    public void unwrappedSecretKeyStaysAnUnboundSecretKeySpec() throws Exception
    {
        for (String t : TRANSFORMS)
        {
            byte[] raw = new byte[32];
            RANDOM.nextBytes(raw);

            byte[] wrapped = wrapper(t).wrap(new SecretKeySpec(raw, "AES"));
            Key back = unwrapper(t).unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertEquals(SecretKeySpec.class, back.getClass(),
                    t + ": a secret key unwrap must not acquire native residency");
            Assertions.assertTrue(Arrays.areEqual(raw, back.getEncoded()),
                    t + ": the unwrapped secret must be the one that was wrapped");
        }
    }

    // -----------------------------------------------------------------
    // loud failure — the contract question MT-10 had to settle
    // -----------------------------------------------------------------

    /**
     * Unwrapping a family JSLFIPS does not serve fails LOUDLY rather than
     * borrowing someone else's KeyFactory.
     *
     * <p>Ed25519 is the real case, not a synthetic one: the {@code edec}
     * sources are nonfips-only, so JSLFIPS registers no Ed25519 KeyFactory
     * while both JSL and SunEC (JDK 15+) do. A bare
     * {@code KeyFactory.getInstance("Ed25519")} therefore succeeds on this
     * JVM, which is precisely the fall-through that must not happen — and the
     * precondition is asserted, so if JSLFIPS ever gains Ed25519 this test
     * says so instead of passing vacuously.
     *
     * <p>Refusing is the right answer rather than a gap: the alternative is
     * handing back a key from outside the module under a provider whose whole
     * purpose is that the work happens inside it.
     */
    @Test
    public void unwrapOfAFamilyTheModuleDoesNotServeFailsLoudly() throws Exception
    {
        Assertions.assertNull(fips.getService("KeyFactory", "Ed25519"),
                "JSLFIPS now serves an Ed25519 KeyFactory, so this test no longer "
                        + "discriminates — pick another unserved family");

        Provider elsewhere;
        try
        {
            elsewhere = KeyFactory.getInstance("Ed25519").getProvider();
        }
        catch (NoSuchAlgorithmException e)
        {
            Assertions.fail("no installed provider serves Ed25519, so there is nothing for a "
                    + "bare lookup to fall through TO and this test cannot discriminate");
            return;
        }

        for (String t : TRANSFORMS)
        {
            byte[] garbage = new byte[t.startsWith("RSA") ? 256 : 40];
            RANDOM.nextBytes(garbage);

            final Cipher c = unwrapper(t);
            NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> c.unwrap(garbage, "Ed25519", Cipher.PRIVATE_KEY),
                    t + ": a JSLFIPS unwrap must not borrow " + elsewhere.getName()
                            + "'s Ed25519 KeyFactory");
            Assertions.assertTrue(
                    e.getMessage().contains("provider JSLFIPS serves no KeyFactory for Ed25519"),
                    t + ": the failure must name the provider and the algorithm, got: "
                            + e.getMessage());
        }
    }
}
