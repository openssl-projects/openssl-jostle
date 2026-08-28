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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-16: the KTS ciphers resolve their inner lookups from the provider
 * INSTANCE they belong to, not from whatever the provider NAME resolves to.
 *
 * <h2>What was wrong</h2>
 *
 * {@code RSAKEMCipherSpi} and {@code MLKEMKTSCipherSpi} take a KEK and hand
 * the entire unwrap — {@code wrappedKeyType} included, so the asymmetric arms
 * really do reach it — to an inner AES key-wrap {@code Cipher}, and they
 * derive that KEK with a {@code MessageDigest}. MT-5 pinned both lookups by
 * NAME, which fixed the original defect (they had resolved to SUN and to a
 * hard-coded {@code "JSL"}). A name is not identity, though:
 * {@code removeProvider} + {@code addProvider} swaps which instance a name
 * resolves to, and {@code getInstance(alg, Provider)} never required
 * registration at all. Either way the inner work landed in a DIFFERENT
 * instance from the one the caller asked for — and since the inner cipher
 * performs the whole unwrap, the key it returned was bound to that other
 * instance, so this provider then refused it (MT-14).
 *
 * <h2>Why the tests look like this</h2>
 *
 * The failure mode is name RE-RESOLUTION, so every test here runs with a
 * SECOND live instance of the same provider class installed under the name,
 * and drives the outer {@code Cipher} from a first instance that is not the
 * one the name points at. {@link #theNameResolvesToTheOtherInstance} asserts
 * that arrangement is real before anything relies on it — without it the
 * whole file could pass against a single instance and prove nothing.
 *
 * <p>Two observables discriminate, and both are needed because they cover
 * different lookups:
 *
 * <ol>
 * <li><b>Capability.</b> The outer instance is a {@link StrippedJostleProvider}
 *     missing exactly one service the wrap needs, while the instance under the
 *     name has it. Under a name pin the wrap succeeds by borrowing; under an
 *     instance pin it fails loudly. This is the only observable for the KDF
 *     digest — SHA-256 is SHA-256 whoever computes it, so nothing about the
 *     output could ever distinguish the two.</li>
 * <li><b>Key binding.</b> An asymmetric unwrap must return a key carrying the
 *     OUTER instance. Under a name pin it carries the other one. This is the
 *     caller-visible half: a key bound elsewhere is refused by the very
 *     provider that produced it.</li>
 * </ol>
 *
 * <p>Only the PRIVATE_KEY arm is driven for binding. Both asymmetric arms
 * reach the same single line in the inner cipher
 * ({@code UnwrappedKeys.keyFactory(providerInstance, alg)}), and which arm
 * runs cannot change which INSTANCE is passed to it — that is what MT-16
 * moves. The arms themselves are pinned, on both providers, by
 * {@code UnwrappedKeyBindingTest} and {@code FIPSUnwrappedKeyBindingTest}.
 *
 * <p>Class-per-JVM ({@code forkEvery = 1}) is what makes swapping the global
 * provider registry safe here; the swap is still undone after every test so
 * the methods stay independent of each other.
 */
public class KtsProviderInstancePinningTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * id-aes256-wrap. The KTS ciphers pick the key-wrap OID from the KEK
     * length and every test here asks for a 256-bit KEK, so this is the one
     * they resolve.
     */
    private static final String KW_OID_AES256 = "2.16.840.1.101.3.4.1.45";

    /** The instance the NAME resolves to. Never the one a Cipher is built from. */
    private Provider named;

    /** Whatever was installed before, restored afterwards. */
    private Provider original;

    @BeforeEach
    void installASecondInstanceUnderTheName()
    {
        original = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (original != null)
        {
            Security.removeProvider(JostleProvider.PROVIDER_NAME);
        }
        named = new JostleProvider();
        Assertions.assertTrue(Security.addProvider(named) > 0,
                "the second instance must install under the JSL name, or nothing here "
                        + "distinguishes a name pin from an instance pin");
    }

    @AfterEach
    void restore()
    {
        Security.removeProvider(JostleProvider.PROVIDER_NAME);
        if (original != null)
        {
            Security.addProvider(original);
        }
    }

    /**
     * The arrangement every other test depends on: the name resolves to
     * {@link #named}, and a freshly built instance is a different object that
     * the name does NOT point at.
     */
    @Test
    public void theNameResolvesToTheOtherInstance()
    {
        Provider outer = new JostleProvider();
        Assertions.assertNotSame(outer, named, "two instances must be distinct objects");
        Assertions.assertSame(named, Security.getProvider(JostleProvider.PROVIDER_NAME),
                "the name must resolve to the second instance");
        Assertions.assertSame(named,
                Security.getProvider(JostleProvider.PROVIDER_NAME),
                "and must keep resolving to it for the duration of a test");
    }

    // -----------------------------------------------------------------
    // Capability: the inner lookups come from the outer instance
    // -----------------------------------------------------------------

    @Test
    public void mlkemKts_kdfDigestComesFromTheOuterInstance() throws Exception
    {
        digestPinIsOnTheInstance("ML-KEM", mlkemKek());
    }

    @Test
    public void rsaKts_kdfDigestComesFromTheOuterInstance() throws Exception
    {
        digestPinIsOnTheInstance("RSA-KTS-KEM-KWS", rsaKek());
    }

    @Test
    public void mlkemKts_aesKeyWrapComesFromTheOuterInstance() throws Exception
    {
        keyWrapPinIsOnTheInstance("ML-KEM", mlkemKek());
    }

    @Test
    public void rsaKts_aesKeyWrapComesFromTheOuterInstance() throws Exception
    {
        keyWrapPinIsOnTheInstance("RSA-KTS-KEM-KWS", rsaKek());
    }

    /**
     * The outer instance cannot compute SHA-256; the instance under the name
     * can. A name pin borrows it and the wrap succeeds; an instance pin fails.
     */
    private void digestPinIsOnTheInstance(String transform, String kekAlgorithm) throws Exception
    {
        Provider outer = new StrippedJostleProvider("MessageDigest", "SHA-256");
        Assertions.assertNotNull(named.getService("MessageDigest", "SHA-256"),
                "the instance under the NAME must still serve SHA-256, or this proves "
                        + "absence rather than instance identity");

        Exception e = Assertions.assertThrows(Exception.class,
                () -> wrapThrough(outer, transform, kekAlgorithm),
                transform + ": a wrap through an instance that cannot compute the KDF digest "
                        + "must fail, not borrow the digest from the instance the NAME "
                        + "resolves to");
        String msg = rootMessage(e);
        Assertions.assertTrue(msg.contains("does not serve SHA-256"),
                transform + ": must fail at the KDF digest pin naming the digest; got: " + msg);
    }

    /** The same for the second lookup: the AES key wrap. */
    private void keyWrapPinIsOnTheInstance(String transform, String kekAlgorithm) throws Exception
    {
        Provider outer = new StrippedJostleProvider("Cipher", KW_OID_AES256);
        Assertions.assertNotNull(named.getService("Cipher", KW_OID_AES256),
                "the instance under the NAME must still serve the AES key wrap, or this "
                        + "proves absence rather than instance identity");

        Exception e = Assertions.assertThrows(Exception.class,
                () -> wrapThrough(outer, transform, kekAlgorithm),
                transform + ": a wrap through an instance that cannot key-wrap must fail, not "
                        + "borrow the key wrap from the instance the NAME resolves to");
        String msg = rootMessage(e);
        Assertions.assertTrue(msg.contains("does not serve the AES key wrap"),
                transform + ": must fail at the AES key-wrap pin; got: " + msg);
        Assertions.assertTrue(msg.contains(KW_OID_AES256),
                transform + ": must name the key-wrap OID; got: " + msg);
    }

    /**
     * Positive control for the two above. Without it they would both pass
     * against a KTS cipher that refused every instance, capable or not.
     */
    @Test
    public void aFullyCapableOuterInstanceWraps() throws Exception
    {
        Assertions.assertNotNull(wrapThrough(new JostleProvider(), "ML-KEM", mlkemKek()));
        Assertions.assertNotNull(
                wrapThrough(new JostleProvider(), "RSA-KTS-KEM-KWS", rsaKek()));
    }

    // -----------------------------------------------------------------
    // Ordering: the inner Cipher is resolved BEFORE the decapsulation
    // -----------------------------------------------------------------

    /**
     * MT-10's rule, applied one layer down: an unwrap must perform its
     * ciphertext-INDEPENDENT lookups before the ciphertext-dependent
     * decrypt, or the exception TYPE reports whether the decrypt succeeded.
     *
     * <p>The property asserted is therefore not "it throws" but "it throws the
     * SAME thing either way". Against an instance that cannot serve the AES
     * key wrap, a valid encapsulation and a structurally invalid one must both
     * raise {@code NoSuchAlgorithmException}. Before the resolution was
     * hoisted the invalid one raised {@code InvalidKeyException} from the
     * decapsulation instead, and the pair told a caller whether its
     * ciphertext was well formed.
     *
     * <p><b>The valid arm alone would not discriminate</b> — it raises
     * {@code NoSuchAlgorithmException} whichever order the two steps run in.
     * The invalid arm is the one that moves, so both are here and the
     * assertion is on their agreement.
     *
     * <p><b>RSA-KTS specifically, and ML-KEM cannot substitute.</b> ML-KEM
     * decapsulation never fails — implicit rejection returns a pseudo-random
     * secret for any input of the right length — so no ciphertext makes its
     * decap arm throw and there is nothing to distinguish. RSASVE does fail on
     * an encapsulation whose integer value exceeds the modulus, which is what
     * the all-ones input below is.
     *
     * <p>The KDF digest is deliberately NOT part of this: {@code deriveKek}
     * maps its {@code NoSuchAlgorithmException} to {@code InvalidKeyException},
     * the same type a failed decapsulation raises, so that arm is already
     * indistinguishable. Do not "unify" the two arms by letting the digest
     * failure through as {@code NoSuchAlgorithmException} — that would create
     * the very oracle this test forbids.
     */
    @Test
    public void rsaKts_unservedKeyWrapFailsTheSameWayForValidAndInvalidCiphertext()
            throws Exception
    {
        Provider stripped = new StrippedJostleProvider("Cipher", KW_OID_AES256);
        Provider full = new JostleProvider();

        KeyPair kek = keyPair(stripped, "RSA");

        // A genuinely valid encapsulation, produced by an instance that CAN
        // key-wrap. The public half crosses by encoding — the sanctioned
        // route — because the wrap side refuses a key bound elsewhere.
        java.security.PublicKey pubForFull = java.security.KeyFactory.getInstance("RSA", full)
                .generatePublic(new java.security.spec.X509EncodedKeySpec(
                        kek.getPublic().getEncoded()));
        Cipher w = Cipher.getInstance("RSA-KTS-KEM-KWS", full);
        w.init(Cipher.WRAP_MODE, pubForFull, ktsSpec(), RANDOM);
        byte[] valid = w.wrap(new SecretKeySpec(new byte[32], "AES"));

        // Long enough to clear the length check, and an encapsulation whose
        // integer value exceeds any 2048-bit modulus, so RSASVE refuses it.
        byte[] invalid = new byte[valid.length];
        java.util.Arrays.fill(invalid, (byte) 0xFF);

        Exception onValid = Assertions.assertThrows(Exception.class,
                () -> unwrapThrough(stripped, kek.getPrivate(), valid));
        Exception onInvalid = Assertions.assertThrows(Exception.class,
                () -> unwrapThrough(stripped, kek.getPrivate(), invalid));

        Assertions.assertEquals(NoSuchAlgorithmException.class, onValid.getClass(),
                "a valid encapsulation against an instance that cannot key-wrap must report "
                        + "the missing key wrap; got: " + rootMessage(onValid));
        Assertions.assertEquals(NoSuchAlgorithmException.class, onInvalid.getClass(),
                "an INVALID encapsulation must report the same missing key wrap, not the "
                        + "decapsulation failure — the exception type must not depend on the "
                        + "ciphertext; got: " + rootMessage(onInvalid));
        Assertions.assertTrue(rootMessage(onInvalid).contains("does not serve the AES key wrap"),
                "and must say so at the key-wrap pin; got: " + rootMessage(onInvalid));
    }

    /**
     * Control: the same instance, once it CAN key-wrap, does distinguish the
     * two ciphertexts — so the agreement asserted above is the pin doing its
     * job, not the KTS cipher having become unable to tell them apart.
     */
    @Test
    public void rsaKts_aCapableInstanceStillRejectsAnInvalidEncapsulation() throws Exception
    {
        Provider outer = new JostleProvider();
        KeyPair kek = keyPair(outer, "RSA");

        Cipher w = Cipher.getInstance("RSA-KTS-KEM-KWS", outer);
        w.init(Cipher.WRAP_MODE, kek.getPublic(), ktsSpec(), RANDOM);
        byte[] valid = w.wrap(new SecretKeySpec(new byte[32], "AES"));
        Assertions.assertNotNull(unwrapThrough(outer, kek.getPrivate(), valid));

        byte[] invalid = new byte[valid.length];
        java.util.Arrays.fill(invalid, (byte) 0xFF);
        Exception e = Assertions.assertThrows(Exception.class,
                () -> unwrapThrough(outer, kek.getPrivate(), invalid));
        Assertions.assertEquals(java.security.InvalidKeyException.class, e.getClass(),
                "a capable instance must reject an invalid encapsulation as an unwrap "
                        + "failure; got: " + rootMessage(e));
    }

    private Key unwrapThrough(Provider p, java.security.PrivateKey kekPrivate, byte[] wrapped)
            throws Exception
    {
        Cipher u = Cipher.getInstance("RSA-KTS-KEM-KWS", p);
        u.init(Cipher.UNWRAP_MODE, kekPrivate, ktsSpec(), RANDOM);
        return u.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }

    // -----------------------------------------------------------------
    // Binding: the key an asymmetric unwrap returns
    // -----------------------------------------------------------------

    @Test
    public void mlkemKts_unwrappedPrivateKeyIsBoundToTheOuterInstance() throws Exception
    {
        unwrappedKeyIsBoundToTheOuterInstance("ML-KEM", mlkemKek());
    }

    @Test
    public void rsaKts_unwrappedPrivateKeyIsBoundToTheOuterInstance() throws Exception
    {
        unwrappedKeyIsBoundToTheOuterInstance("RSA-KTS-KEM-KWS", rsaKek());
    }

    /**
     * Wrap a private key through an instance the NAME does not point at, then
     * unwrap it through the same instance, and require the key that comes back
     * to carry THAT instance. Under the name pin it carried the other one —
     * and the outer provider then refused its own output.
     */
    private void unwrappedKeyIsBoundToTheOuterInstance(String transform, String kekAlgorithm)
            throws Exception
    {
        Provider outer = new JostleProvider();
        KeyPair kek = keyPair(outer, kekAlgorithm);
        KeyPair payload = eightAlignedRsaKeyPair(outer);

        Cipher w = Cipher.getInstance(transform, outer);
        w.init(Cipher.WRAP_MODE, kek.getPublic(), ktsSpec(), RANDOM);
        byte[] wrapped = w.wrap(payload.getPrivate());

        Cipher u = Cipher.getInstance(transform, outer);
        u.init(Cipher.UNWRAP_MODE, kek.getPrivate(), ktsSpec(), RANDOM);
        Key back = u.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);

        Assertions.assertTrue(back instanceof OSSLKey,
                transform + ": the unwrapped key must be a Jostle key, not a foreign one; got "
                        + back.getClass().getName());
        Assertions.assertSame(outer, ((OSSLKey) back).getSpec().getProviderInstance(),
                transform + ": the unwrapped key must be bound to the instance that unwrapped "
                        + "it, not to whatever the provider NAME resolves to");
    }

    /**
     * And the consequence a caller sees: a key bound elsewhere is refused by
     * the provider that produced it, so binding is not a detail of the spec
     * object. Driven through {@code Signature} because that is where MT-14's
     * check lives.
     */
    @Test
    public void anUnwrappedPrivateKeyWorksImmediatelyInTheInstanceThatUnwrappedIt()
            throws Exception
    {
        Provider outer = new JostleProvider();
        KeyPair kek = keyPair(outer, mlkemKek());
        KeyPair payload = eightAlignedRsaKeyPair(outer);

        Cipher w = Cipher.getInstance("ML-KEM", outer);
        w.init(Cipher.WRAP_MODE, kek.getPublic(), ktsSpec(), RANDOM);
        byte[] wrapped = w.wrap(payload.getPrivate());

        Cipher u = Cipher.getInstance("ML-KEM", outer);
        u.init(Cipher.UNWRAP_MODE, kek.getPrivate(), ktsSpec(), RANDOM);
        Key back = u.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);

        byte[] message = new byte[64];
        RANDOM.nextBytes(message);

        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA", outer);
        signer.initSign((java.security.PrivateKey) back);
        signer.update(message);
        byte[] sig = signer.sign();

        java.security.Signature verifier =
                java.security.Signature.getInstance("SHA256withRSA", outer);
        verifier.initVerify(payload.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig),
                "the unwrapped private key must be the one that was wrapped");

        message[0] ^= (byte) 0x01;
        verifier.initVerify(payload.getPublic());
        verifier.update(message);
        Assertions.assertFalse(verifier.verify(sig),
                "a tampered message must not verify — otherwise the check above would pass "
                        + "against a verifier that always says yes");
    }

    /**
     * The SECRET_KEY arm is unaffected and stays unbound, consistent with
     * MT-10 and MT-14: a secret key has no native residency and no provider to
     * belong to. Here so that a future change tightening the asymmetric arms
     * cannot quietly drag this one along.
     */
    @Test
    public void unwrappedSecretKeyStaysAnUnboundSecretKeySpec() throws Exception
    {
        Provider outer = new JostleProvider();
        KeyPair kek = keyPair(outer, mlkemKek());

        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);

        Cipher w = Cipher.getInstance("ML-KEM", outer);
        w.init(Cipher.WRAP_MODE, kek.getPublic(), ktsSpec(), RANDOM);
        byte[] wrapped = w.wrap(new SecretKeySpec(raw, "AES"));

        Cipher u = Cipher.getInstance("ML-KEM", outer);
        u.init(Cipher.UNWRAP_MODE, kek.getPrivate(), ktsSpec(), RANDOM);
        Key back = u.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        Assertions.assertFalse(back instanceof OSSLKey,
                "a secret key must not acquire native residency through unwrap");
        Assertions.assertArrayEquals(raw, back.getEncoded());
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static String mlkemKek()
    {
        return "ML-KEM-768";
    }

    private static String rsaKek()
    {
        return "RSA";
    }

    private static KeyPair keyPair(Provider p, String algorithm) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, p);
        if ("RSA".equals(algorithm))
        {
            kpg.initialize(2048, RANDOM);
        }
        return kpg.generateKeyPair();
    }

    /**
     * An RSA key pair whose PKCS#8 private encoding is a multiple of 8 bytes.
     *
     * <p>The KTS ciphers wrap with AES-KW (id-aes256-wrap), not KWP, and
     * RFC 3394 requires 8-byte-aligned input — so most asymmetric encodings
     * cannot be wrapped at all. RSA is the family whose encoding length
     * actually varies (1216-1218 bytes at 2048 bits, according to how many
     * leading bits its INTEGERs carry), so a short search finds an aligned
     * one; every other family measured has a fixed, unaligned length.
     *
     * <p>Bounded and self-describing on failure rather than looping forever:
     * roughly one key in three qualifies, so exhausting the bound means
     * something changed about the encoding, not bad luck.
     */
    private static KeyPair eightAlignedRsaKeyPair(Provider p) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", p);
        kpg.initialize(2048, RANDOM);
        for (int i = 0; i != 64; i++)
        {
            KeyPair kp = kpg.generateKeyPair();
            if (kp.getPrivate().getEncoded().length % 8 == 0)
            {
                return kp;
            }
        }
        throw new IllegalStateException(
                "no 8-aligned RSA PKCS#8 encoding in 64 tries — AES-KW needs one and about a "
                        + "third of keys should qualify, so the encoding has changed shape");
    }

    /** A 256-bit KEK derived by KDF3/SHA-256 — what every test here drives. */
    private static KTSParameterSpec ktsSpec()
    {
        return new KTSParameterSpec.Builder("AES", 256)
                .withKdfAlgorithm(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_kdf_kdf3,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)))
                .build();
    }

    private byte[] wrapThrough(Provider outer, String transform, String kekAlgorithm)
            throws Exception
    {
        KeyPair kek = keyPair(outer, kekAlgorithm);
        Cipher c = Cipher.getInstance(transform, outer);
        c.init(Cipher.WRAP_MODE, kek.getPublic(), ktsSpec(), RANDOM);
        byte[] cek = new byte[32];
        RANDOM.nextBytes(cek);
        return c.wrap(new SecretKeySpec(cek, "AES"));
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
}
