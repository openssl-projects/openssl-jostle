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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
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

/**
 * MT-10: a key produced by {@code Cipher.unwrap} belongs to the provider that
 * unwrapped it.
 *
 * <h2>What was wrong</h2>
 *
 * Every {@code engineUnwrap} in the provider called
 * {@code KeyFactory.getInstance(wrappedKeyAlgorithm)} with no provider, so JCA
 * resolved it against the installed list in order — normally SUN. Two
 * consequences:
 *
 * <ol>
 * <li>A JSLFIPS unwrap produced a key not resident in the FIPS lib ctx.
 *     Undetectable behaviourally: a SUN EC key signs the same bytes.</li>
 * <li>The returned key was foreign, so the very next Jostle operation on it
 *     failed MT-14's provider-instance isolation check — {@code unwrap} handed
 *     back something the unwrapping provider itself refuses.</li>
 * </ol>
 *
 * <h2>What is asserted</h2>
 *
 * Not "unwrap returned something". The discriminating assertions are that the
 * unwrapped key's spec carries the unwrapping provider INSTANCE, and that the
 * key works immediately in that provider's own Signature — the property a
 * caller depends on and the one the old code broke. A test that only compared
 * encodings passed throughout the defect's life
 * ({@code RSAOAEPCipherTest.testOAEP_WrapUnwrap_PublicKey_roundTrip} did
 * exactly that).
 *
 * <p>{@link #unwrapDoesNotFallThroughToTheProviderJcaWouldPick} is the one
 * that would have caught the original defect: it first establishes that a bare
 * {@code KeyFactory.getInstance("EC")} resolves to some OTHER provider on this
 * JVM, so the trap is live, and only then requires the unwrapped key to be
 * ours.
 *
 * <p>The FIPS half lives in {@code FIPSUnwrappedKeyBindingTest} — different
 * native library, different lib ctx, so neither substitutes for the other.
 */
public class UnwrappedKeyBindingTest
{
    /**
     * The three unwrapping SPIs MT-10 covers, by transformation.
     * {@code AESWrapPad} (KWP) rather than {@code AESWrap}: KW requires an
     * input length that is a multiple of 8, which a PKCS#8 EC key is not.
     */
    private static final String[] TRANSFORMS =
            {"AESWrapPad", "RSA/ECB/OAEPPadding", "RSA/ECB/PKCS1Padding"};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static Provider jsl;
    private static KeyPair rsaKek;
    private static SecretKey aesKek;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", jsl);
        kpg.initialize(2048, RANDOM);
        rsaKek = kpg.generateKeyPair();

        KeyGenerator kg = KeyGenerator.getInstance("AES", jsl);
        kg.init(256, RANDOM);
        aesKek = kg.generateKey();
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static Cipher wrapper(String transform) throws Exception
    {
        Cipher c = Cipher.getInstance(transform, jsl);
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
        Cipher c = Cipher.getInstance(transform, jsl);
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

    /**
     * A fresh EC P-256 pair from the JVM default provider — deliberately NOT
     * from Jostle. It stands in for a peer's key arriving over the wire, which
     * is the realistic source of wrapped key material, and it makes the point
     * that what comes BACK is bound to the unwrapping provider whatever went
     * in. P-256 keeps both halves inside a 2048-bit RSA OAEP-SHA-256 payload
     * (190 bytes).
     */
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

    // -----------------------------------------------------------------
    // PUBLIC_KEY / PRIVATE_KEY — the binding contract
    // -----------------------------------------------------------------

    @Test
    public void unwrappedPublicKeyIsBoundToTheUnwrappingProvider() throws Exception
    {
        for (String t : TRANSFORMS)
        {
            KeyPair kp = payload();
            byte[] wrapped = wrapper(t).wrap(kp.getPublic());
            Key back = unwrapper(t).unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);

            Assertions.assertSame(jsl, boundTo(back),
                    t + ": an unwrapped public key must be bound to the provider that "
                            + "unwrapped it");
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(), back.getEncoded(),
                    t + ": the unwrapped key must still be the key that was wrapped");
        }
    }

    @Test
    public void unwrappedPrivateKeyIsBoundAndImmediatelyUsableInThatProvider() throws Exception
    {
        for (String t : TRANSFORMS)
        {
            KeyPair kp = payload();
            byte[] wrapped = wrapper(t).wrap(kp.getPrivate());
            Key back = unwrapper(t).unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);

            Assertions.assertSame(jsl, boundTo(back),
                    t + ": an unwrapped private key must be bound to the provider that "
                            + "unwrapped it");

            //
            // The caller-visible half. Before MT-10 the key came back from
            // whatever provider JCA picked, and this line threw
            // InvalidKeyException("... created by a different Jostle provider
            // instance ...") — unwrap handing back a key its own provider
            // refuses. Signing with it and verifying against the ORIGINAL
            // public key also proves the private half survived the round trip.
            //
            byte[] msg = new byte[1 + RANDOM.nextInt(200)];
            RANDOM.nextBytes(msg);

            Signature signer = Signature.getInstance("SHA256withECDSA", jsl);
            signer.initSign((java.security.PrivateKey) back, RANDOM);
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withECDSA", jsl);
            verifier.initVerify(
                    KeyFactory.getInstance("EC", jsl).generatePublic(
                            new java.security.spec.X509EncodedKeySpec(
                                    kp.getPublic().getEncoded())));
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig),
                    t + ": the unwrapped private key must be the one that was wrapped");

            //
            // Negative half: the same signature must not verify against a
            // tampered message, or "verify() returned true" proves nothing.
            //
            msg[RANDOM.nextInt(msg.length)] ^= (byte) 0x01;
            Signature tampered = Signature.getInstance("SHA256withECDSA", jsl);
            tampered.initVerify(
                    KeyFactory.getInstance("EC", jsl).generatePublic(
                            new java.security.spec.X509EncodedKeySpec(
                                    kp.getPublic().getEncoded())));
            tampered.update(msg);
            Assertions.assertFalse(tampered.verify(sig),
                    t + ": a tampered message must not verify");
        }
    }

    // -----------------------------------------------------------------
    // SECRET_KEY — deliberately unchanged
    // -----------------------------------------------------------------

    /**
     * A SECRET_KEY unwrap still returns a plain {@code SecretKeySpec}, and
     * that is the decision, not an omission. Secret keys have no native
     * residency, so there is no provider for one to be bound to and no
     * isolation check for it to fail — the same line MT-14 drew.
     */
    @Test
    public void unwrappedSecretKeyStaysAnUnboundSecretKeySpec() throws Exception
    {
        for (String t : TRANSFORMS)
        {
            byte[] raw = new byte[32];
            RANDOM.nextBytes(raw);
            SecretKey cek = new SecretKeySpec(raw, "AES");

            byte[] wrapped = wrapper(t).wrap(cek);
            Key back = unwrapper(t).unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertEquals(SecretKeySpec.class, back.getClass(),
                    t + ": a secret key unwrap must not acquire native residency");
            Assertions.assertFalse(back instanceof OSSLKey,
                    t + ": a secret key must not be bound to a provider instance");
            Assertions.assertTrue(Arrays.areEqual(raw, back.getEncoded()),
                    t + ": the unwrapped secret must be the one that was wrapped");
        }
    }

    // -----------------------------------------------------------------
    // the defect itself
    // -----------------------------------------------------------------

    /**
     * The test that would have caught MT-10.
     *
     * <p>Its discriminating branch executes on any JVM where a non-Jostle
     * provider serves an EC KeyFactory and sits ahead of JSL in JCA order —
     * i.e. every stock JDK, since SUN/SunEC are installed by default and
     * {@code Security.addProvider} appends. The precondition is asserted
     * rather than assumed: if a bare lookup ever resolved to JSL the trap
     * would be inert and the rest would pass vacuously.
     */
    @Test
    public void unwrapDoesNotFallThroughToTheProviderJcaWouldPick() throws Exception
    {
        Provider jcaWouldPick = KeyFactory.getInstance("EC").getProvider();
        Assertions.assertNotSame(jsl, jcaWouldPick,
                "the trap is not live on this JVM: a bare KeyFactory.getInstance(\"EC\") "
                        + "already resolves to JSL, so this test cannot distinguish the fixed "
                        + "code from the broken code");

        for (String t : TRANSFORMS)
        {
            KeyPair kp = payload();
            byte[] wrapped = wrapper(t).wrap(kp.getPublic());
            Key back = unwrapper(t).unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);

            Assertions.assertSame(jsl, boundTo(back),
                    t + ": unwrap resolved its KeyFactory through JCA order and returned a "
                            + jcaWouldPick.getName() + " key");
        }
    }

    // -----------------------------------------------------------------
    // loud failure
    // -----------------------------------------------------------------

    /**
     * An algorithm the unwrapping provider does not serve fails LOUDLY, and
     * fails BEFORE the decrypt.
     *
     * <p>The ordering is the point, and the deliberately-garbage ciphertext is
     * how it is proven: a resolution done after decrypting would report the
     * decrypt failure ({@code InvalidKeyException}) instead. Ordering is not
     * cosmetic — with an unserved algorithm, resolving second would make a
     * valid ciphertext raise {@code NoSuchAlgorithmException} and an invalid
     * one {@code InvalidKeyException}, which is a padding oracle.
     */
    @Test
    public void unwrapOfAnUnservedAlgorithmFailsLoudlyBeforeDecrypting() throws Exception
    {
        Assertions.assertNull(jsl.getService("KeyFactory", "NoSuchKeyAlgorithm"),
                "the sentinel algorithm must not actually be served");

        for (String t : TRANSFORMS)
        {
            byte[] garbage = new byte[t.startsWith("RSA") ? 256 : 40];
            RANDOM.nextBytes(garbage);

            final Cipher c = unwrapper(t);
            NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> c.unwrap(garbage, "NoSuchKeyAlgorithm", Cipher.PRIVATE_KEY),
                    t + ": an unserved wrapped-key algorithm must fail typed, not fall through "
                            + "to whatever JCA has installed");
            Assertions.assertTrue(e.getMessage().contains("provider JSL serves no KeyFactory for "
                            + "NoSuchKeyAlgorithm"),
                    t + ": the failure must name the provider and the algorithm, got: "
                            + e.getMessage());
        }
    }

    /**
     * The same refusal applies to a REAL algorithm another provider serves —
     * proof the gate is about what THIS provider serves, not about the name
     * being nonsense.
     *
     * <p>The algorithm is DISCOVERED, not named: the first KeyFactory
     * BouncyCastle registers that JSL does not. Naming one would go stale, and
     * three plausible guesses were already wrong — JSL aliases
     * {@code DiffieHellman}, {@code RSASSA-PSS} and {@code XDH}, so its
     * KeyFactory surface turns out to be a superset of the stock JDK's and the
     * JDK offers no instance of this cell at all. BouncyCastle does
     * ({@code ElGamal}, the GOST and DSTU families), and it is already on the
     * test classpath.
     */
    @Test
    public void unwrapWillNotBorrowAnAlgorithmAnotherProviderServes() throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        Provider bc = Security.getProvider("BC");

        String borrowable = null;
        for (Provider.Service svc : bc.getServices())
        {
            if ("KeyFactory".equals(svc.getType())
                    && jsl.getService("KeyFactory", svc.getAlgorithm()) == null)
            {
                borrowable = svc.getAlgorithm();
                break;
            }
        }
        Assertions.assertNotNull(borrowable,
                "BC registers no KeyFactory that JSL lacks, so there is nothing for a bare "
                        + "lookup to fall through TO and this test cannot discriminate");

        // The trap must be live: a bare lookup has to succeed, or refusing it
        // proves nothing about pinning.
        Assertions.assertNotSame(jsl, KeyFactory.getInstance(borrowable).getProvider(),
                borrowable + " resolves to JSL after all");

        final String alg = borrowable;
        for (String t : TRANSFORMS)
        {
            byte[] garbage = new byte[t.startsWith("RSA") ? 256 : 40];
            RANDOM.nextBytes(garbage);

            final Cipher c = unwrapper(t);
            NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> c.unwrap(garbage, alg, Cipher.PRIVATE_KEY),
                    t + ": unwrap must not borrow BC's " + alg + " KeyFactory");
            Assertions.assertTrue(
                    e.getMessage().contains("provider JSL serves no KeyFactory for " + alg),
                    t + ": the failure must name the provider and the algorithm, got: "
                            + e.getMessage());
        }
    }
}
