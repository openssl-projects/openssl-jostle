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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

/**
 * Verifies the Java 15+ EdEC interface implementations on Jostle keys:
 * - JOEdPublicKey.getPoint() returns an EdECPoint other providers can rebuild a usable PublicKey from.
 * - JOEdPrivateKey.getBytes() returns the raw scalar bytes other providers can rebuild a usable PrivateKey from.
 *
 * Round-trips through SunEC (the JDK's built-in provider) and BouncyCastle confirm that
 * Jostle's decoding of the OpenSSL-encoded key matches the format consumed by other providers.
 */
public class EdECInterfaceTest
{
    private static final SecureRandom random = new SecureRandom();

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


    //
    // getPoint() round-trip via SunEC
    //
    @Test
    public void testEd25519GetPoint_RoundTripViaSunEC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED25519, "ED25519", null);
    }

    @Test
    public void testEd448GetPoint_RoundTripViaSunEC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED448, "ED448", null);
    }

    //
    // getPoint() round-trip via BC
    //
    @Test
    public void testEd25519GetPoint_RoundTripViaBC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED25519, "ED25519", BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void testEd448GetPoint_RoundTripViaBC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED448, "ED448", BouncyCastleProvider.PROVIDER_NAME);
    }


    //
    // getBytes() round-trip via SunEC
    //
    @Test
    public void testEd25519GetBytes_RoundTripViaSunEC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED25519, "ED25519", 32, null);
    }

    @Test
    public void testEd448GetBytes_RoundTripViaSunEC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED448, "ED448", 57, null);
    }

    //
    // getBytes() round-trip via BC
    //
    @Test
    public void testEd25519GetBytes_RoundTripViaBC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED25519, "ED25519", 32, BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void testEd448GetBytes_RoundTripViaBC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED448, "ED448", 57, BouncyCastleProvider.PROVIDER_NAME);
    }


    /**
     * Generate a Jostle keypair, sign a message with the Jostle private key, then
     * extract the EdECPoint from the Jostle public key and reconstruct a public
     * key in the target provider. The reconstructed key must verify the Jostle
     * signature.
     *
     * @param namedSpec   NamedParameterSpec.ED25519 / NamedParameterSpec.ED448
     * @param algorithm   "ED25519" / "ED448" — used for KeyPairGenerator and Jostle Signature
     * @param targetProv  null for the JDK's default provider (SunEC); non-null for a named provider (e.g. BC)
     */
    private static void getPointRoundTrip(NamedParameterSpec namedSpec, String algorithm, String targetProv) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Assertions.assertTrue(kp.getPublic() instanceof EdECPublicKey,
                "Jostle public key must implement EdECPublicKey on Java 15+");

        byte[] message = new byte[1024];
        random.nextBytes(message);

        Signature joSigner = Signature.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        joSigner.initSign(kp.getPrivate());
        joSigner.update(message);
        byte[] sig = joSigner.sign();

        EdECPublicKey edPub = (EdECPublicKey) kp.getPublic();
        EdECPoint point = edPub.getPoint();
        Assertions.assertNotNull(point);
        Assertions.assertNotNull(point.getY());

        EdECPublicKeySpec spec = new EdECPublicKeySpec(namedSpec, point);
        KeyFactory kf = (targetProv == null)
                ? KeyFactory.getInstance(algorithm)
                : KeyFactory.getInstance(algorithm, targetProv);
        PublicKey reconstructed = kf.generatePublic(spec);

        Signature verifier = (targetProv == null)
                ? Signature.getInstance(algorithm)
                : Signature.getInstance(algorithm, targetProv);
        verifier.initVerify(reconstructed);
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig),
                "rebuilt " + algorithm + " key from EdECPoint must verify the Jostle signature ("
                        + (targetProv == null ? "default" : targetProv) + " provider)");
    }

    /**
     * Symmetric: extract raw bytes from Jostle private key, reconstruct in the
     * target provider, sign with the reconstructed key, and verify with the
     * Jostle public key.
     */
    private static void getBytesRoundTrip(NamedParameterSpec namedSpec, String algorithm, int expectedLen, String targetProv) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Assertions.assertTrue(kp.getPrivate() instanceof EdECPrivateKey,
                "Jostle private key must implement EdECPrivateKey on Java 15+");

        EdECPrivateKey edPriv = (EdECPrivateKey) kp.getPrivate();
        Optional<byte[]> bytes = edPriv.getBytes();
        Assertions.assertTrue(bytes.isPresent());
        Assertions.assertEquals(expectedLen, bytes.get().length,
                "raw scalar length should be " + expectedLen + " bytes for " + algorithm);

        EdECPrivateKeySpec spec = new EdECPrivateKeySpec(namedSpec, bytes.get());
        KeyFactory kf = (targetProv == null)
                ? KeyFactory.getInstance(algorithm)
                : KeyFactory.getInstance(algorithm, targetProv);
        PrivateKey reconstructed = kf.generatePrivate(spec);

        byte[] message = new byte[1024];
        random.nextBytes(message);

        Signature signer = (targetProv == null)
                ? Signature.getInstance(algorithm)
                : Signature.getInstance(algorithm, targetProv);
        signer.initSign(reconstructed);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig),
                "Jostle must verify a signature made by the reconstructed " + algorithm + " key ("
                        + (targetProv == null ? "default" : targetProv) + " provider)");
    }
}
