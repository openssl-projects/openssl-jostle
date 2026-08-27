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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Cross-implementation agreement for the four TLS hybrid KEM groups: JSL
 * against {@link HybridRef}, an independent composition of BouncyCastle's
 * ML-KEM and ECDH primitives, both directions.
 *
 * <p>BouncyCastle registers no JCE name for these groups (its
 * {@code MLKEM768-X25519-SHA3-256} family is the composite-ML-KEM draft, a
 * different construction with a KDF), so the reference is the specification's
 * own composition — see {@link HybridRef} for why that is the sanctioned
 * fallback and what it states independently.
 *
 * <p>Encapsulation is randomised, so byte-equality between two independent
 * encapsulations is unavailable. Each direction is checked by having the OTHER
 * implementation recover the secret instead: a wrong-but-self-consistent
 * Jostle cannot satisfy BC's primitives, and a wrong concatenation ORDER
 * fails even though both halves are individually correct.
 */
public class MLXKEMAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final String[] GUARDED_TYPES = {"KeyPairGenerator", "KeyGenerator", "KeyFactory"};

    private static final String MLXKEM_PREFIX = "org.openssl.jostle.jcajce.provider.mlxkem.";

    private static final int TRIALS = 5;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The production ordering flag must match the reference's own reading of
     * the draft. Both halves of a hybrid secret are individually correct under
     * a flipped flag, so nothing else in this file can separate the two — the
     * agreement tests below compose with {@link HybridRef}'s literal, which
     * would silently follow a flipped production value if they read it.
     */
    @Test
    public void orderingFlagMatchesTheDraft()
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            Assertions.assertEquals(HybridRef.mlkemFirst(spec), spec.isMlkemFirst(),
                    spec.getName() + ": ML-KEM-first ordering");
        }
    }

    /**
     * JSL encapsulates to a key share the reference composed; the reference
     * must recover the same secret from its own halves.
     */
    @Test
    public void jslEncapsulate_referenceDecapsulates() throws Exception
    {
        SecureRandom random = seededRandom("jslEncapsulate_referenceDecapsulates");

        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            for (int t = 0; t < TRIALS; t++)
            {
                HybridRef.Party peer = HybridRef.Party.generate(spec, random);

                PublicKey jslView = KeyFactory.getInstance(spec.getName(), JSL)
                        .generatePublic(new MLXKEMPublicKeySpec(spec, peer.share));

                SecretKeyWithEncapsulation sent = encapsulate(spec, jslView);

                Assertions.assertEquals(spec.getSharedSecretBytes(), sent.getEncoded().length,
                        spec.getName() + ": shared secret length");
                Assertions.assertTrue(Arrays.areEqual(
                                sent.getEncoded(), peer.decapsulate(sent.getEncapsulation())),
                        spec.getName() + ": reference must recover JSL's secret");
            }
        }
    }

    /**
     * The reference encapsulates to a JSL-generated key share; JSL must
     * recover the same secret. The opposite code path from the test above —
     * this one drives Jostle's decapsulation against an encapsulation Jostle
     * did not produce.
     */
    @Test
    public void referenceEncapsulate_jslDecapsulates() throws Exception
    {
        SecureRandom random = seededRandom("referenceEncapsulate_jslDecapsulates");

        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            for (int t = 0; t < TRIALS; t++)
            {
                KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
                byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();

                byte[][] made = HybridRef.encapsulate(spec, share, random);

                byte[] recovered = decapsulate(spec, kp.getPrivate(), made[0]).getEncoded();

                Assertions.assertTrue(Arrays.areEqual(made[1], recovered),
                        spec.getName() + ": JSL must recover the reference's secret");
            }
        }
    }

    /**
     * Negative path, per half. Damaging the ML-KEM half and damaging the ECDH
     * half exercise different code inside the provider, and a decapsulation
     * that ignored one of them entirely would still pass a single
     * "flip any byte" check.
     *
     * <p>ML-KEM is designed to decapsulate a damaged ciphertext to a
     * DIFFERENT secret rather than fail, so this asserts divergence and
     * tolerates an exception; a damaged EC point is usually rejected outright.
     */
    @Test
    public void tamperingEitherHalfChangesTheSecret() throws Exception
    {
        SecureRandom random = seededRandom("tamperingEitherHalfChangesTheSecret");

        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            KeyPair kp = KeyPairGenerator.getInstance(spec.getName(), JSL).generateKeyPair();
            byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
            byte[][] made = HybridRef.encapsulate(spec, share, random);
            byte[] good = decapsulate(spec, kp.getPrivate(), made[0]).getEncoded();

            Assertions.assertTrue(Arrays.areEqual(made[1], good), spec.getName() + ": control");

            // Offsets from the reference's own split. The ECDH half's length
            // is measured from a freshly generated key, so this stays right if
            // a curve's encoding ever changed.
            int ecdhLen = HybridRef.ecdhPublicLength(spec, random);
            int mlkemStart = HybridRef.mlkemFirst(spec) ? 0 : ecdhLen;
            int ecdhStart = HybridRef.mlkemFirst(spec) ? made[0].length - ecdhLen : 0;

            assertDiverges(spec, kp, made[0], mlkemStart, good, "ML-KEM half");
            assertDiverges(spec, kp, made[0], ecdhStart, good, "ECDH half");
        }
    }

    /**
     * Every hybrid service the provider registers is DRIVEN, not merely
     * listed. Discovery is from {@code getServices()}, so a group added to
     * {@code ProvMLXKEM} and to nothing else fails here rather than going
     * quietly untested.
     */
    @Test
    public void everyRegisteredHybridServiceIsDriven() throws Exception
    {
        ProviderSurfaceGuard.assertEveryServiceDriven(Security.getProvider(JSL),
                MLXKEM_PREFIX, "hybrid KEM (JSL)", GUARDED_TYPES,
                new ProviderSurfaceGuard.ServiceDriver()
                {
                    public void drive(String type, String alg) throws Exception
                    {
                        MLXKEMParameterSpec spec = MLXKEMParameterSpec.fromName(alg);
                        KeyPair kp = KeyPairGenerator.getInstance(alg, JSL).generateKeyPair();

                        if ("KeyPairGenerator".equals(type))
                        {
                            Assertions.assertEquals(spec.getSharedSecretBytes() * 8,
                                    encapsulate(spec, kp.getPublic()).getEncoded().length * 8, alg);
                        }
                        else if ("KeyFactory".equals(type))
                        {
                            byte[] raw = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
                            MLXKEMPublicKey back = (MLXKEMPublicKey) KeyFactory.getInstance(alg, JSL)
                                    .generatePublic(new MLXKEMPublicKeySpec(spec, raw));
                            Assertions.assertTrue(Arrays.areEqual(raw, back.getPublicData()), alg);
                        }
                        else if ("KeyGenerator".equals(type))
                        {
                            SecretKeyWithEncapsulation sent = encapsulate(spec, kp.getPublic());
                            Assertions.assertTrue(Arrays.areEqual(sent.getEncoded(),
                                            decapsulate(spec, kp.getPrivate(), sent.getEncapsulation()).getEncoded()),
                                    alg);
                        }
                        else
                        {
                            throw new AssertionError("undriven service type " + type + " for " + alg);
                        }
                    }
                });
    }

    // -----------------------------------------------------------------

    private void assertDiverges(MLXKEMParameterSpec spec, KeyPair kp, byte[] encapsulation,
                                int offset, byte[] good, String what) throws Exception
    {
        byte[] bad = Arrays.clone(encapsulation);
        bad[offset] ^= (byte) 0x01;

        boolean diverged;
        try
        {
            diverged = !Arrays.areEqual(good, decapsulate(spec, kp.getPrivate(), bad).getEncoded());
        }
        catch (RuntimeException e)
        {
            diverged = true;
        }
        Assertions.assertTrue(diverged, spec.getName() + ": tampering the " + what
                + " must not yield the original secret");
    }

    private static SecretKeyWithEncapsulation encapsulate(MLXKEMParameterSpec spec, PublicKey pub)
            throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), JSL);
        kg.init(KEMGenerateSpec.builder()
                .withPublicKey(pub)
                .withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                .build());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }

    private static SecretKeyWithEncapsulation decapsulate(MLXKEMParameterSpec spec,
                                                          java.security.PrivateKey priv,
                                                          byte[] encapsulation) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), JSL);
        kg.init(KEMExtractSpec.builder()
                .withPrivate(priv)
                .withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8)
                .withEncapsulatedKey(encapsulation)
                .build());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }
}
