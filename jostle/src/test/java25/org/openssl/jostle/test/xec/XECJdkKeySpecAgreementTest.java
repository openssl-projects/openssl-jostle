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

package org.openssl.jostle.test.xec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * The JDK XEC key specs on the 25 legs: getKeySpec against BouncyCastle, and the u-coordinate bounds.
 */
public class XECJdkKeySpecAgreementTest
{
    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * getKeySpec answers the JDK XEC specs for both halves on both curves, and the specs agree with BouncyCastle
     * and decode back to the same encodings on both providers.
     */
    @Test
    public void jdkKeySpecsAgreeWithBouncyCastle() throws Exception
    {
        for (String alg : new String[]{"X25519", "X448"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, JostleProvider.PROVIDER_NAME).generateKeyPair();
            KeyFactory jslKf = KeyFactory.getInstance(alg, JostleProvider.PROVIDER_NAME);
            KeyFactory bcKf = KeyFactory.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);

            XECPublicKeySpec pub = jslKf.getKeySpec(kp.getPublic(), XECPublicKeySpec.class);
            XECPublicKeySpec bcPub = bcKf.getKeySpec(bcKf.generatePublic(
                    new X509EncodedKeySpec(kp.getPublic().getEncoded())), XECPublicKeySpec.class);
            Assertions.assertEquals(bcPub.getU(), pub.getU(), alg);
            Assertions.assertEquals(alg, ((NamedParameterSpec) pub.getParams()).getName(), alg);
            Assertions.assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), jslKf.generatePublic(pub).getEncoded()));
            Assertions.assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), bcKf.generatePublic(pub).getEncoded()));

            XECPrivateKeySpec priv = jslKf.getKeySpec(kp.getPrivate(), XECPrivateKeySpec.class);
            XECPrivateKeySpec bcPriv = bcKf.getKeySpec(bcKf.generatePrivate(
                    new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())), XECPrivateKeySpec.class);
            Assertions.assertTrue(Arrays.areEqual(bcPriv.getScalar(), priv.getScalar()), alg);
            PrivateKey back = jslKf.generatePrivate(priv);
            Assertions.assertTrue(Arrays.areEqual(((XECPrivateKey) kp.getPrivate()).getScalar().get(),
                    ((XECPrivateKey) back).getScalar().get()), alg);
        }
    }

    /** A negative u is refused on both providers; u at or above p still reduces mod p. */
    @Test
    public void negativeUIsRefusedAndLargeUReduces() throws Exception
    {
        KeyFactory jslKf = KeyFactory.getInstance("X25519", JostleProvider.PROVIDER_NAME);
        KeyFactory bcKf = KeyFactory.getInstance("X25519", BouncyCastleProvider.PROVIDER_NAME);
        XECPublicKeySpec negative = new XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger.ONE.negate());
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> jslKf.generatePublic(negative));
        Assertions.assertEquals("XECPublicKeySpec u-coordinate is negative", e.getMessage());
        Assertions.assertThrows(InvalidKeySpecException.class, () -> bcKf.generatePublic(negative));

        BigInteger p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        XECPublicKeySpec atP = new XECPublicKeySpec(NamedParameterSpec.X25519, p.add(BigInteger.ONE));
        Assertions.assertEquals(BigInteger.ONE, ((XECPublicKey) jslKf.generatePublic(atP)).getU());
        Assertions.assertEquals(BigInteger.ONE, ((XECPublicKey) bcKf.generatePublic(atP)).getU());
    }
}
