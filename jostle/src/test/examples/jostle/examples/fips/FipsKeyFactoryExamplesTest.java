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

package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.MLXKEMPublicKey;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.MLXKEMPublicKeySpec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key factories in the FIPS module. A key object belongs to the provider that made it: JSLFIPS refuses a JSL
 * key object, private or public, so an operation never runs outside the module by accident. To move a key
 * between the two, encode it and decode it through the target provider's factory.
 */
public class FipsKeyFactoryExamplesTest
        extends FipsExamples
{
    /**
     * A JSL key is refused by a JSLFIPS signature; the same key, encoded and decoded through the JSLFIPS
     * factory, is accepted.
     */
    @Test
    public void moveAKeyFromJslToJslFips()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
        kpg.initialize(2048);
        KeyPair jslPair = kpg.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withRSA", "JSLFIPS");
        Assertions.assertThrows(InvalidKeyException.class, () -> s.initSign(jslPair.getPrivate()));

        KeyFactory kf = KeyFactory.getInstance("RSA", "JSLFIPS");
        PrivateKey moved = kf.generatePrivate(new PKCS8EncodedKeySpec(jslPair.getPrivate().getEncoded()));
        s.initSign(moved);
        s.update(new byte[]{1, 2, 3});
        Assertions.assertTrue(s.sign().length > 0);
    }

    /**
     * Decode the classical families' encodings. The DSA key comes from JSL, since the module as installed here
     * generates none; importing it is allowed.
     */
    @Test
    public void classicalEncodingsRoundTrip()
            throws Exception
    {
        String[] factories = {"RSA", "EC", "DH", "DSA"};
        String[] generators = {"RSA", "EC", "DH", "DSA"};
        String[] providers = {"JSLFIPS", "JSLFIPS", "JSLFIPS", "JSL"};
        int[] sizes = {2048, 256, 2048, 2048};
        for (int i = 0; i < factories.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(generators[i], providers[i]);
            kpg.initialize(sizes[i]);
            KeyPair kp = kpg.generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance(factories[i], "JSLFIPS");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(), factories[i]);
            Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded(), factories[i]);
        }
    }

    /**
     * The Edwards and post-quantum families, one factory per parameter set or a generic one, where the module
     * serves them.
     */
    @Test
    public void edwardsAndPostQuantumEncodingsRoundTrip()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("KeyFactory", "ML-DSA-65") != null);
        String[] factories = {"ED25519", "ED448", "ED", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "MLDSA", "ML-KEM-512",
                "ML-KEM-768", "ML-KEM-1024", "MLKEM", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S",
                "SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S",
                "SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S",
                "SLH-DSA-SHAKE-256F", "SLHDSA"};
        for (String name : factories)
        {
            String generator = name.equals("ED") ? "ED448" : name.equals("MLDSA") ? "ML-DSA-65"
                    : name.equals("MLKEM") ? "ML-KEM-768" : name.equals("SLHDSA") ? "SLH-DSA-SHA2-128F" : name;
            KeyPair kp = KeyPairGenerator.getInstance(generator, "JSLFIPS").generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance(name, "JSLFIPS");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            Assertions.assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(), name);
            Assertions.assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded(), name);
        }
    }

    /**
     * An RSA public key from its modulus and exponent.
     */
    @Test
    public void rsaFromComponents()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSLFIPS");
        kpg.initialize(2048);
        RSAPublicKey original = (RSAPublicKey) kpg.generateKeyPair().getPublic();
        BigInteger n = original.getModulus();
        KeyFactory kf = KeyFactory.getInstance("RSA", "JSLFIPS");
        PublicKey rebuilt = kf.generatePublic(new RSAPublicKeySpec(n, original.getPublicExponent()));
        Assertions.assertArrayEquals(original.getEncoded(), rebuilt.getEncoded());
    }

    /**
     * A hybrid public key from the raw share a TLS key exchange carries. Hybrid keys have no encoding, so they
     * cannot move between providers at all.
     */
    @Test
    public void hybridPublicKeyFromItsRawShare()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("KeyFactory", "X25519MLKEM768") != null);
        for (String name : new String[]{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(name, "JSLFIPS").generateKeyPair();
            byte[] share = ((MLXKEMPublicKey) kp.getPublic()).getPublicData();
            MLXKEMPublicKey back = (MLXKEMPublicKey) KeyFactory.getInstance(name, "JSLFIPS").generatePublic(
                    new MLXKEMPublicKeySpec(MLXKEMParameterSpec.fromName(name), share));
            Assertions.assertArrayEquals(share, back.getPublicData(), name);
        }
    }
}
