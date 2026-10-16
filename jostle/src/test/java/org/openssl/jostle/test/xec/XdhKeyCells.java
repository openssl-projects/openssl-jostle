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

import org.junit.jupiter.api.Assertions;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE cells shared by the base and FIPS XDH tests, each taking the provider name under test.
 */
public final class XdhKeyCells
{
    private XdhKeyCells()
    {
    }

    /** A public key held by another provider: only its encoding is visible. */
    private static PublicKey foreignPublic(PublicKey key)
    {
        byte[] enc = key.getEncoded();
        return new PublicKey()
        {
            @Override
            public String getAlgorithm()
            {
                return key.getAlgorithm();
            }

            @Override
            public String getFormat()
            {
                return "X.509";
            }

            @Override
            public byte[] getEncoded()
            {
                return enc.clone();
            }
        };
    }

    /**
     * A KeyFactory registered under one curve's name decodes only that curve's keys, on the X.509, PKCS#8 and
     * translateKey paths; the XDH factory decodes both.
     */
    public static void namedFactoryHoldsItsCurve(String provider) throws Exception
    {
        for (String[] pair : new String[][]{{"X25519", "X448"}, {"X448", "X25519"}})
        {
            String own = pair[0];
            String other = pair[1];
            KeyPair kp = KeyPairGenerator.getInstance(other, provider).generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance(own, provider);
            String want = "expected " + own + " but got " + other;

            InvalidKeySpecException pub = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())), own);
            Assertions.assertEquals(want, pub.getMessage());
            InvalidKeySpecException priv = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())), own);
            Assertions.assertEquals(want, priv.getMessage());
            InvalidKeyException translated = Assertions.assertThrows(InvalidKeyException.class,
                    () -> kf.translateKey(foreignPublic(kp.getPublic())), own);
            Assertions.assertEquals(want, translated.getMessage());

            KeyFactory any = KeyFactory.getInstance("XDH", provider);
            PublicKey back = any.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey backPriv = any.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            Assertions.assertEquals(other, back.getAlgorithm());
            Assertions.assertEquals(other, backPriv.getAlgorithm());
            Assertions.assertEquals(own, KeyFactory.getInstance(own, provider).generatePublic(
                    new X509EncodedKeySpec(KeyPairGenerator.getInstance(own, provider).generateKeyPair()
                            .getPublic().getEncoded())).getAlgorithm());
        }
    }
}
