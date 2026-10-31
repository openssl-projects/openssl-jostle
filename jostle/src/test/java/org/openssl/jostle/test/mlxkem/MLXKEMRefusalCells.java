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
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Where a hybrid group refuses a ciphertext or a share, ours and {@link HybridRef}'s answers side by side, per group,
 * shared by the base and FIPS agreement tests. The classical half decides: an X25519 or X448 point is any string of
 * the right length, so only the all-zero point is refused, and at the agreement; a SecP point that is off the curve
 * is refused at the decode. The ML-KEM half never refuses: a damaged one decapsulates to a different secret.
 */
public final class MLXKEMRefusalCells
{
    private MLXKEMRefusalCells()
    {
    }

    private static boolean isSecP(MLXKEMParameterSpec spec)
    {
        return spec.getName().startsWith("SecP");
    }

    /** BouncyCastle's refusal of the all-zero X point names the curve: X25519 or X448. */
    private static String xCurve(MLXKEMParameterSpec spec)
    {
        return spec.getName().substring(0, spec.getName().indexOf("MLKEM"));
    }

    /**
     * An all-zero ciphertext is refused typed, naming the group, with the library's error as the cause; so is a
     * damaged SecP point. A damaged ML-KEM half, and a damaged X point, decapsulate to a different secret. HybridRef
     * is driven with the same damage to a ciphertext of its own.
     */
    public static void refusedDecapsulations(String provider, MLXKEMParameterSpec spec, SecureRandom random)
            throws Exception
    {
        String name = spec.getName();
        KeyPair kp = KeyPairGenerator.getInstance(name, provider).generateKeyPair();
        SecretKeyWithEncapsulation sent = encapsulate(provider, spec, kp.getPublic());
        byte[] ct = sent.getEncapsulation();
        byte[] good = sent.getEncoded();

        HybridRef.Party peer = HybridRef.Party.generate(spec, random);
        byte[][] made = HybridRef.encapsulate(spec, peer.share, random);
        Assertions.assertArrayEquals(made[1], peer.decapsulate(made[0]), name + ": reference control");

        int ecdhLen = HybridRef.ecdhPublicLength(spec, random);
        int mlkemStart = HybridRef.mlkemFirst(spec) ? 0 : ecdhLen;
        int ecdhStart = HybridRef.mlkemFirst(spec) ? ct.length - ecdhLen : 0;
        // A SecP point starts with its 0x04 form byte, which stays intact so the coordinates are what is damaged.
        int ecdhByte = ecdhStart + (isSecP(spec) ? 1 : 0);

        assertRefused(provider, spec, kp.getPrivate(), new byte[ct.length]);
        if (isSecP(spec))
        {
            Assertions.assertEquals("Incorrect length for infinity encoding", Assertions.assertThrows(
                    IllegalArgumentException.class, () -> peer.decapsulate(new byte[made[0].length])).getMessage());
        }
        else
        {
            Assertions.assertEquals(xCurve(spec) + " agreement failed", Assertions.assertThrows(
                    IllegalStateException.class, () -> peer.decapsulate(new byte[made[0].length])).getMessage());
        }

        Assertions.assertFalse(Arrays.areEqual(good, decapsulate(provider, spec, kp.getPrivate(),
                flip(ct, mlkemStart)).getEncoded()), name + ": damaged ML-KEM half");
        Assertions.assertFalse(Arrays.areEqual(made[1], peer.decapsulate(flip(made[0], mlkemStart))),
                name + ": reference, damaged ML-KEM half");

        if (isSecP(spec))
        {
            assertRefused(provider, spec, kp.getPrivate(), flip(ct, ecdhByte));
            Assertions.assertEquals("Invalid point coordinates", Assertions.assertThrows(
                    IllegalArgumentException.class, () -> peer.decapsulate(flip(made[0], ecdhByte))).getMessage());
        }
        else
        {
            Assertions.assertFalse(Arrays.areEqual(good, decapsulate(provider, spec, kp.getPrivate(),
                    flip(ct, ecdhByte)).getEncoded()), name + ": damaged X point");
            Assertions.assertFalse(Arrays.areEqual(made[1], peer.decapsulate(flip(made[0], ecdhByte))),
                    name + ": reference, damaged X point");
        }

        // The same private key still decapsulates the genuine ciphertext.
        Assertions.assertArrayEquals(good, decapsulate(provider, spec, kp.getPrivate(), ct).getEncoded(), name);
    }

    /**
     * An all-zero share: a SecP group refuses it at the KeyFactory; an X group imports it, since any string of the
     * right length is an X point, and refuses it at encapsulation, typed and naming the group. HybridRef refuses it
     * at its encapsulation.
     */
    public static void allZeroShare(String provider, MLXKEMParameterSpec spec, SecureRandom random) throws Exception
    {
        String name = spec.getName();
        int shareLen = HybridRef.Party.generate(spec, random).share.length;
        KeyFactory kf = KeyFactory.getInstance(name, provider);
        MLXKEMPublicKeySpec zero = new MLXKEMPublicKeySpec(spec, new byte[shareLen]);
        if (isSecP(spec))
        {
            Assertions.assertEquals("unable to decode " + name + " public key", Assertions.assertThrows(
                    InvalidKeySpecException.class, () -> kf.generatePublic(zero)).getMessage());
            Assertions.assertEquals("Incorrect length for infinity encoding", Assertions.assertThrows(
                    IllegalArgumentException.class,
                    () -> HybridRef.encapsulate(spec, new byte[shareLen], random)).getMessage());
        }
        else
        {
            PublicKey imported = kf.generatePublic(zero);
            Assertions.assertArrayEquals(new byte[shareLen], ((MLXKEMPublicKey) imported).getPublicData(), name);
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> encapsulate(provider, spec, imported));
            Assertions.assertEquals("invalid public key for " + name, e.getMessage());
            Assertions.assertTrue(e.getCause() instanceof OpenSSLException, name);
            Assertions.assertEquals(xCurve(spec) + " agreement failed", Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> HybridRef.encapsulate(spec, new byte[shareLen], random)).getMessage());
        }
    }

    private static void assertRefused(String provider, MLXKEMParameterSpec spec, PrivateKey priv, byte[] ct)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> decapsulate(provider, spec, priv, ct));
        Assertions.assertEquals("invalid encapsulation for " + spec.getName(), e.getMessage());
        Assertions.assertTrue(e.getCause() instanceof OpenSSLException, spec.getName());
    }

    private static byte[] flip(byte[] b, int i)
    {
        byte[] c = Arrays.clone(b);
        c[i] ^= 1;
        return c;
    }

    private static SecretKeyWithEncapsulation encapsulate(String provider, MLXKEMParameterSpec spec, PublicKey pub)
            throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), provider);
        kg.init(KEMGenerateSpec.builder().withPublicKey(pub).withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8).withNoKdf().build());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }

    private static SecretKeyWithEncapsulation decapsulate(String provider, MLXKEMParameterSpec spec, PrivateKey priv,
                                                          byte[] ct) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(spec.getName(), provider);
        kg.init(KEMExtractSpec.builder().withPrivate(priv).withAlgorithmName("AES")
                .withKeySizeInBits(spec.getSharedSecretBytes() * 8).withEncapsulatedKey(ct).withNoKdf().build());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }
}
