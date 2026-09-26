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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key factories turn encodings and components back into keys: a public key from its X.509
 * `SubjectPublicKeyInfo`, a private key from its PKCS#8 encoding. A key belongs to the provider that made it;
 * to use one with another provider, encode it and decode it through that provider's factory.
 */
public class KeyFactoryExamplesTest
        extends JslExamples
{
    /**
     * Decode the classical families' encodings. `XDH` decodes X25519 and X448 keys, and `ED` both Edwards
     * curves.
     */
    @Test
    public void classicalEncodingsRoundTrip()
            throws Exception
    {
        String[] factories = {"RSA", "EC", "DSA", "DH", "ED25519", "ED448", "ED", "X25519", "X448", "XDH"};
        String[] generators = {"RSA", "EC", "DSA", "DH", "ED25519", "ED448", "ED448", "X25519", "X448", "X25519"};
        for (int i = 0; i < factories.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(generators[i], "JSL").generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance(factories[i], "JSL");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(), factories[i]);
            Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded(), factories[i]);
        }
    }

    /**
     * Decode the post-quantum families' encodings, one factory per parameter set, or the generic `MLDSA`,
     * `MLKEM` and `SLHDSA` factories, which take a key of any set.
     */
    @Test
    public void postQuantumEncodingsRoundTrip()
            throws Exception
    {
        String[] factories = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "MLDSA", "ML-KEM-512", "ML-KEM-768",
                "ML-KEM-1024", "MLKEM", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S",
                "SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S",
                "SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S",
                "SLH-DSA-SHAKE-256F", "SLHDSA"};
        for (String name : factories)
        {
            String generator = name.equals("MLDSA") ? "ML-DSA-65" : name.equals("MLKEM") ? "ML-KEM-768"
                    : name.equals("SLHDSA") ? "SLH-DSA-SHA2-128F" : name;
            KeyPair kp = KeyPairGenerator.getInstance(generator, "JSL").generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance(name, "JSL");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(), name);
            Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded(), name);
        }
    }

    /**
     * Build an RSA public key from its modulus and exponent, and read them back with `getKeySpec`.
     */
    @Test
    public void rsaFromComponents()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
        kpg.initialize(2048);
        RSAPublicKey original = (RSAPublicKey) kpg.generateKeyPair().getPublic();
        BigInteger n = original.getModulus();
        BigInteger e = original.getPublicExponent();

        KeyFactory kf = KeyFactory.getInstance("RSA", "JSL");
        PublicKey rebuilt = kf.generatePublic(new RSAPublicKeySpec(n, e));
        RSAPublicKeySpec read = kf.getKeySpec(rebuilt, RSAPublicKeySpec.class);
        Assertions.assertEquals(n, read.getModulus());
        Assertions.assertArrayEquals(original.getEncoded(), rebuilt.getEncoded());
    }

    /**
     * A hybrid KEM key has no X.509 encoding: its public half travels as the raw share a TLS key exchange
     * carries, rebuilt with `MLXKEMPublicKeySpec`.
     */
    @Test
    public void hybridPublicKeyFromItsRawShare()
            throws Exception
    {
        String[] names = {"X25519MLKEM768", "X448MLKEM1024", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"};
        for (String name : names)
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSL").generateKeyPair();
            byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
            KeyFactory kf = KeyFactory.getInstance(name, "JSL");
            MLXKEMPublicKey back = (MLXKEMPublicKey) kf.generatePublic(
                    new MLXKEMPublicKeySpec(MLXKEMParameterSpec.fromName(name), share));
            Assertions.assertArrayEquals(share, back.getPublicData(), name);
        }
    }
}
