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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPrivateKey;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

/**
 * Contract coverage for the four TLS hybrid KEM groups: the properties a
 * caller can observe that are NOT about the shared secret agreeing.
 * {@link MLXKEMAgreementTest} owns the cryptographic agreement; this file owns
 * the encoding contract, the key semantics that follow from it, and the SPI
 * state machine.
 *
 * <p>The unusual property throughout is that these keys have <b>no
 * encoding</b>. Nothing registers a codec for the groups, so {@code
 * getEncoded()} and {@code getFormat()} both answer null on both halves — and
 * a null encoding has knock-on consequences (no serialization, identity-based
 * equality) that a caller will meet whether or not anyone wrote them down.
 */
public class MLXKEMTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static KeyPair keyPair(MLXKEMParameterSpec spec) throws Exception
    {
        return KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
    }

    // -----------------------------------------------------------------
    // The no-encoding contract, and what follows from it
    // -----------------------------------------------------------------

    /**
     * Both halves of every group report no encoding, in BOTH the ways
     * {@link java.security.Key} offers. A key that returned a format string
     * while {@code getEncoded()} answered null would send a caller looking for
     * bytes that are not there.
     */
    @Test
    public void neitherHalfHasAnEncoding() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            Assertions.assertNull(kp.getPublic().getEncoded(), spec.getName() + " public getEncoded");
            Assertions.assertNull(kp.getPublic().getFormat(), spec.getName() + " public getFormat");
            Assertions.assertNull(kp.getPrivate().getEncoded(), spec.getName() + " private getEncoded");
            Assertions.assertNull(kp.getPrivate().getFormat(), spec.getName() + " private getFormat");
        }
    }

    /**
     * A null encoding makes these keys non-serializable, because
     * {@code java.security.KeyRep} needs the encoded form. Worth pinning as a
     * caller-visible consequence: it fails at {@code writeObject}, not at
     * read-back, so a caller who serializes a keystore of mixed key types
     * finds out immediately.
     */
    @Test
    public void keysAreNotSerializable() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            assertNotSerializable(spec, kp.getPublic());
            assertNotSerializable(spec, kp.getPrivate());
        }
    }

    private void assertNotSerializable(MLXKEMParameterSpec spec, Object key)
    {
        try
        {
            ObjectOutputStream oos = new ObjectOutputStream(new ByteArrayOutputStream());
            oos.writeObject(key);
            oos.close();
            Assertions.fail(spec.getName() + ": " + key.getClass().getSimpleName()
                    + " serialized, but it has no encoded form to reconstruct from");
        }
        catch (NotSerializableException e)
        {
            // Expected: the key class is not Serializable at all.
        }
        catch (java.io.IOException e)
        {
            // A KeyRep-based failure surfaces as some other IOException;
            // either way the object did not serialize.
        }
    }

    /**
     * With no encoding there is nothing to compare, so equality falls back to
     * identity — {@code AsymmetricKeyImpl.equals} returns false when either
     * encoding is null rather than calling two unavailable encodings equal.
     * Pinned because it differs from every other Jostle key family, where two
     * instances of the same key DO compare equal.
     */
    @Test
    public void equalityIsIdentityBecauseThereIsNoEncodingToCompare() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            MLXKEMPublicKey a = (MLXKEMPublicKey) kp.getPublic();
            MLXKEMPublicKey b = (MLXKEMPublicKey) ((MLXKEMPrivateKey) kp.getPrivate()).getPublicKey();

            Assertions.assertEquals(a, a, spec.getName() + ": a key equals itself");
            // Same underlying PKEY, different wrapper: not equal, because
            // there are no encodings to compare.
            Assertions.assertNotEquals(a, b, spec.getName() + ": distinct wrappers are not equal");
            Assertions.assertTrue(Arrays.areEqual(a.getPublicData(), b.getPublicData()),
                    spec.getName() + ": ...even though they hold the same public share");
        }
    }

    // -----------------------------------------------------------------
    // Raw public import / export
    // -----------------------------------------------------------------

    /**
     * The raw share is the only way in and out, so it must round-trip and it
     * must be the right length for the group.
     */
    @Test
    public void rawPublicShareRoundTrips() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            byte[] raw = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();

            KeyFactory kf = KeyFactory.getInstance(spec.getName(), JSL);
            MLXKEMPublicKey back = (MLXKEMPublicKey) kf.generatePublic(new MLXKEMPublicKeySpec(spec, raw));
            Assertions.assertTrue(Arrays.areEqual(raw, back.getPublicData()), spec.getName());

            MLXKEMPublicKeySpec out = kf.getKeySpec(back, MLXKEMPublicKeySpec.class);
            Assertions.assertTrue(Arrays.areEqual(raw, out.getPublicData()), spec.getName() + " getKeySpec");
            Assertions.assertSame(spec, out.getParameterSpec(), spec.getName() + " getKeySpec params");
        }
    }

    /**
     * A share that is one byte short, one byte long, or damaged in the ML-KEM
     * half must be rejected as an {@link InvalidKeySpecException} — not
     * accepted into a key that then fails somewhere unrelated.
     */
    @Test
    public void malformedShareIsRejectedTyped() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            byte[] raw = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
            KeyFactory kf = KeyFactory.getInstance(spec.getName(), JSL);

            for (byte[] bad : new byte[][]{
                    Arrays.copyOfRange(raw, 0, raw.length - 1),
                    Arrays.copyOf(raw, raw.length + 1),
                    new byte[0]})
            {
                Assertions.assertThrows(InvalidKeySpecException.class,
                        () -> kf.generatePublic(new MLXKEMPublicKeySpec(spec, bad)),
                        spec.getName() + ": share of length " + bad.length);
            }
        }
    }

    /**
     * The encoded key specs do not apply here and must say so, rather than
     * throwing something a caller cannot catch by contract.
     */
    @Test
    public void encodedKeySpecsAreRejected() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyFactory kf = KeyFactory.getInstance(spec.getName(), JSL);
            Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new X509EncodedKeySpec(new byte[32])), spec.getName());
            Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new PKCS8EncodedKeySpec(new byte[32])), spec.getName());
        }
    }

    /**
     * Private material never leaves the provider — on any group, including
     * the two whose provider would release it. Pinned per group because the
     * NATIVE behaviour differs (the SecP pair is refused by OpenSSL, the X
     * pair is not) and the uniform Java answer is a deliberate choice on top
     * of that, not something the provider imposes.
     */
    @Test
    public void privateMaterialNeverLeaves() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            KeyFactory kf = KeyFactory.getInstance(spec.getName(), JSL);

            InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.getKeySpec(kp.getPrivate(), MLXKEMPublicKeySpec.class), spec.getName());
            Assertions.assertEquals(
                    "hybrid KEM private keys cannot be exported; they exist only inside the provider",
                    e.getMessage(), spec.getName());

            InvalidKeySpecException i = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new MLXKEMPublicKeySpec(spec, new byte[1])), spec.getName());
            Assertions.assertEquals(
                    "hybrid KEM private keys cannot be imported; they exist only inside the provider",
                    i.getMessage(), spec.getName());
        }
    }

    // -----------------------------------------------------------------
    // Parameter-set plumbing
    // -----------------------------------------------------------------

    /**
     * The four groups are distinct, and their key material is distinct: a key
     * generated for one group must not be usable in another's KeyGenerator.
     * Also pins the two 1024-bearing groups' secret lengths APART — 88 for
     * X448 and 80 for SecP384r1, because P-384's agreement is 48 bytes where
     * X448's is 56. Assuming those match is a mistake that has been made.
     */
    @Test
    public void groupsAreDistinctAndNotInterchangeable() throws Exception
    {
        Set<Integer> secretLengths = new HashSet<Integer>();
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            secretLengths.add(Integer.valueOf(spec.getSharedSecretBytes()));
        }
        Assertions.assertEquals(3, secretLengths.size(),
                "expected three distinct secret lengths (64, 80, 88) across the four groups");
        Assertions.assertEquals(88, MLXKEMParameterSpec.x448_mlkem1024.getSharedSecretBytes());
        Assertions.assertEquals(80, MLXKEMParameterSpec.secp384r1_mlkem1024.getSharedSecretBytes());

        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            for (MLXKEMParameterSpec other : MLXKEMParameterSpec.all())
            {
                if (other == spec)
                {
                    continue;
                }
                KeyGenerator kg = KeyGenerator.getInstance(other.getName(), JSL);
                InvalidAlgorithmParameterException e = Assertions.assertThrows(
                        InvalidAlgorithmParameterException.class,
                        () -> kg.init(KEMGenerateSpec.builder()
                                .withPublicKey(kp.getPublic())
                                .withAlgorithmName("AES")
                                .withKeySizeInBits(other.getSharedSecretBytes() * 8)
                                .build()),
                        other.getName() + " must reject a " + spec.getName() + " key");
                Assertions.assertEquals("expected " + other.getName() + " but got " + spec.getName(),
                        e.getMessage());
            }
        }
    }

    /**
     * A key-size integer is meaningless for a group-based algorithm, and the
     * inherited no-op default would silently accept it.
     */
    @Test
    public void keySizeInitialiseIsRejected() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), JSL);
            InvalidParameterException e = Assertions.assertThrows(InvalidParameterException.class,
                    () -> kpg.initialize(768), spec.getName());
            Assertions.assertEquals(
                    "hybrid KEMs are group-based; use initialize(MLXKEMParameterSpec)", e.getMessage());
        }
    }

    /**
     * A typed generator confirms its own group and refuses any other, and
     * refuses a spec from a different family entirely.
     */
    @Test
    public void initialiseConfirmsTheConstructedGroupOnly() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), JSL);
            kpg.initialize(spec);
            Assertions.assertNotNull(kpg.generateKeyPair(), spec.getName());

            for (MLXKEMParameterSpec other : MLXKEMParameterSpec.all())
            {
                if (other == spec)
                {
                    continue;
                }
                Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                        () -> kpg.initialize(other), spec.getName() + " <- " + other.getName());
            }
            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> kpg.initialize(MLKEMParameterSpec.ml_kem_768), spec.getName() + " <- ML-KEM-768");
            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> kpg.initialize((java.security.spec.AlgorithmParameterSpec) null), spec.getName());
        }
    }

    /**
     * The KeyGenerator is a state machine: generateKey before init is an
     * IllegalStateException, and an extract spec with no encapsulation is
     * rejected at init rather than NPE-ing later.
     */
    @Test
    public void keyGeneratorStateMachineIsGuarded() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), JSL);
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    kg::generateKey, spec.getName());
            Assertions.assertEquals("not initialized", e.getMessage());

            KeyPair kp = keyPair(spec);
            InvalidAlgorithmParameterException n = Assertions.assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () -> kg.init(KEMExtractSpec.builder()
                            .withPrivate(kp.getPrivate())
                            .withAlgorithmName("AES")
                            .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                            .build()),
                    spec.getName());
            Assertions.assertEquals("KEMExtractSpec has no encapsulation", n.getMessage());
        }
    }

    /**
     * The encapsulation length is fixed per group, so a decapsulator must
     * reject one that is a byte short or a byte long rather than reading past
     * it or silently truncating. Probed at exactly ±1, not at some far-off
     * value that an off-by-many check would also reject.
     */
    @Test
    public void encapsulationLengthIsCheckedAtTheBoundary() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            KeyGenerator enc = KeyGenerator.getInstance(spec.getName(), JSL);
            enc.init(KEMGenerateSpec.builder()
                    .withPublicKey(kp.getPublic())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                    .build());
            byte[] good = ((SecretKeyWithEncapsulation) enc.generateKey()).getEncapsulation();

            // Exact length is the positive control: without it the two
            // rejections below would also pass against a decapsulator that
            // refused everything.
            Assertions.assertNotNull(decapsulate(spec, kp, good), spec.getName() + " exact length");

            for (byte[] bad : new byte[][]{
                    Arrays.copyOfRange(good, 0, good.length - 1),
                    Arrays.copyOf(good, good.length + 1)})
            {
                Assertions.assertThrows(RuntimeException.class,
                        () -> decapsulate(spec, kp, bad),
                        spec.getName() + ": encapsulation of length " + bad.length
                                + " must be rejected (exact is " + good.length + ")");
            }
        }
    }

    /**
     * No explicit SecureRandom anywhere — the shape that broke ML-KEM-768/1024
     * in GH issue #34. The 1024-bearing hybrids report 256-bit strength, above
     * the JDK default DRBG's 128, so the SPI has to resolve a
     * strength-appropriate default of its own or the C-side RAND gate refuses
     * the keygen. Runs the whole path, because the gate fires at keygen for
     * some variants and at encapsulate for others.
     */
    @Test
    public void noExplicitSecureRandomWorksAtEveryStrength() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            Assertions.assertEquals(spec.getName().endsWith("1024") ? 256 : 192,
                    spec.getRequiredStrengthBits(), spec.getName());

            KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();

            KeyGenerator enc = KeyGenerator.getInstance(spec.getName(), JSL);
            enc.init(KEMGenerateSpec.builder()
                    .withPublicKey(kp.getPublic())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                    .build());
            SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) enc.generateKey();

            Assertions.assertTrue(Arrays.areEqual(sent.getEncoded(),
                            decapsulate(spec, kp, sent.getEncapsulation()).getEncoded()),
                    spec.getName());
        }
    }

    private static SecretKeyWithEncapsulation decapsulate(MLXKEMParameterSpec spec, KeyPair kp,
                                                          byte[] encapsulation) throws Exception
    {
        KeyGenerator dec = KeyGenerator.getInstance(spec.getName(), JSL);
        dec.init(KEMExtractSpec.builder()
                .withPrivate(kp.getPrivate())
                .withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                .withEncapsulatedKey(encapsulation)
                .build());
        return (SecretKeyWithEncapsulation) dec.generateKey();
    }

    /**
     * One instance, reused: two encapsulations against the same public key
     * must produce DIFFERENT secrets and different encapsulations, and both
     * must decapsulate correctly. A frozen random source, or state left over
     * from the first call, shows up here and nowhere else.
     */
    @Test
    public void reuseProducesFreshRandomisedEncapsulations() throws Exception
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = keyPair(spec);
            KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), JSL);
            KEMGenerateSpec gs = KEMGenerateSpec.builder()
                    .withPublicKey(kp.getPublic())
                    .withAlgorithmName("AES")
                    .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                    .build();

            kg.init(gs);
            SecretKeyWithEncapsulation first = (SecretKeyWithEncapsulation) kg.generateKey();
            kg.init(gs);
            SecretKeyWithEncapsulation second = (SecretKeyWithEncapsulation) kg.generateKey();

            Assertions.assertFalse(Arrays.areEqual(first.getEncoded(), second.getEncoded()),
                    spec.getName() + ": two encapsulations must not share a secret");
            Assertions.assertFalse(Arrays.areEqual(first.getEncapsulation(), second.getEncapsulation()),
                    spec.getName() + ": two encapsulations must differ");

            for (SecretKeyWithEncapsulation sent : new SecretKeyWithEncapsulation[]{first, second})
            {
                KeyGenerator dec = KeyGenerator.getInstance(spec.getName(), JSL);
                dec.init(KEMExtractSpec.builder()
                        .withPrivate(kp.getPrivate())
                        .withAlgorithmName("AES")
                        .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                        .withEncapsulatedKey(sent.getEncapsulation())
                        .build());
                Assertions.assertTrue(Arrays.areEqual(sent.getEncoded(),
                        dec.generateKey().getEncoded()), spec.getName());
            }
        }
    }
}
