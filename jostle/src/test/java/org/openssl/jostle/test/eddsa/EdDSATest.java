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

package org.openssl.jostle.test.eddsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.util.encoders.Hex;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EdDSATest
{

    static SecureRandom secRand = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void testJoToBC() throws Throwable
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(EdDSAParameterSpec.ED25519, secRand);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] msg = new byte[1024];
        secRand.nextBytes(msg);


        Signature signature = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(msg);
        byte[] joSigBytes = signature.sign();


        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey bcPub = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));

        Signature bcVer = Signature.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVer.initVerify(bcPub);
        bcVer.update(msg, 0, msg.length);
        boolean result = bcVer.verify(joSigBytes);

        Assertions.assertTrue(result);

    }

   // @Test
    public void testBCtoJo() throws Throwable
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(EdDSAParameterSpec.ED25519, secRand);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] msg = new byte[1024];
        secRand.nextBytes(msg);

        Signature signature = Signature.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(msg);
        byte[] bcSigBytes = signature.sign();



        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        PublicKey joPub = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));

        Signature joVer = Signature.getInstance("EdDSA", JostleProvider.PROVIDER_NAME);
        joVer.initVerify(joPub);
        joVer.update(msg, 0, msg.length);
        boolean result = joVer.verify(bcSigBytes);

        Assertions.assertTrue(result);

    }


}
