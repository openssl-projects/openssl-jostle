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
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md).
     */
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
        getPointRoundTrip(NamedParameterSpec.ED25519, "ED25519", null,
                seededRandom("testEd25519GetPoint_RoundTripViaSunEC"));
    }

    @Test
    public void testEd448GetPoint_RoundTripViaSunEC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED448, "ED448", null,
                seededRandom("testEd448GetPoint_RoundTripViaSunEC"));
    }

    //
    // getPoint() round-trip via BC
    //
    @Test
    public void testEd25519GetPoint_RoundTripViaBC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED25519, "ED25519", BouncyCastleProvider.PROVIDER_NAME,
                seededRandom("testEd25519GetPoint_RoundTripViaBC"));
    }

    @Test
    public void testEd448GetPoint_RoundTripViaBC() throws Exception
    {
        getPointRoundTrip(NamedParameterSpec.ED448, "ED448", BouncyCastleProvider.PROVIDER_NAME,
                seededRandom("testEd448GetPoint_RoundTripViaBC"));
    }


    //
    // getBytes() round-trip via SunEC
    //
    @Test
    public void testEd25519GetBytes_RoundTripViaSunEC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED25519, "ED25519", 32, null,
                seededRandom("testEd25519GetBytes_RoundTripViaSunEC"));
    }

    @Test
    public void testEd448GetBytes_RoundTripViaSunEC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED448, "ED448", 57, null,
                seededRandom("testEd448GetBytes_RoundTripViaSunEC"));
    }

    //
    // getBytes() round-trip via BC
    //
    @Test
    public void testEd25519GetBytes_RoundTripViaBC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED25519, "ED25519", 32, BouncyCastleProvider.PROVIDER_NAME,
                seededRandom("testEd25519GetBytes_RoundTripViaBC"));
    }

    @Test
    public void testEd448GetBytes_RoundTripViaBC() throws Exception
    {
        getBytesRoundTrip(NamedParameterSpec.ED448, "ED448", 57, BouncyCastleProvider.PROVIDER_NAME,
                seededRandom("testEd448GetBytes_RoundTripViaBC"));
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
    private static void getPointRoundTrip(NamedParameterSpec namedSpec, String algorithm, String targetProv, SecureRandom sr) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        Assertions.assertTrue(kp.getPublic() instanceof EdECPublicKey,
                "Jostle public key must implement EdECPublicKey on Java 15+");

        byte[] message = new byte[1024];
        sr.nextBytes(message);

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
    private static void getBytesRoundTrip(NamedParameterSpec namedSpec, String algorithm, int expectedLen, String targetProv, SecureRandom sr) throws Exception
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
        sr.nextBytes(message);

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

    //
    // Foreign-key acceptance (JCA/TLS gap #5): JSL's Ed Signature must
    // accept a SunEC-decoded key directly — the exact scenario the TLS
    // 1.3 CertificateVerify path hit, where the peer key was decoded by
    // SunEC and handed to Signature.getInstance("Ed25519","JSL").
    //
    @Test
    public void testForeignKeyInterop_SunEC_Ed25519() throws Exception
    {
        foreignKeyInteropViaSunEC("Ed25519");
    }

    @Test
    public void testForeignKeyInterop_SunEC_Ed448() throws Exception
    {
        foreignKeyInteropViaSunEC("Ed448");
    }

    private void foreignKeyInteropViaSunEC(String alg) throws Exception
    {
        SecureRandom sr = seededRandom("foreignKeyInteropViaSunEC_" + alg);

        // SunEC-owned keypair (EdECPublicKey / EdECPrivateKey instances).
        KeyPairGenerator sunKpg = KeyPairGenerator.getInstance(alg, "SunEC");
        KeyPair sunKp = sunKpg.generateKeyPair();

        byte[] msg = new byte[16 + sr.nextInt(256)];
        sr.nextBytes(msg);

        // Sign with SunEC, verify with JSL using SunEC's (foreign) public key.
        Signature sunSigner = Signature.getInstance(alg, "SunEC");
        sunSigner.initSign(sunKp.getPrivate());
        sunSigner.update(msg);
        byte[] sunSig = sunSigner.sign();

        Signature joVerifier = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        joVerifier.initVerify(sunKp.getPublic());
        joVerifier.update(msg);
        Assertions.assertTrue(joVerifier.verify(sunSig),
                alg + ": JSL failed to verify a SunEC signature using SunEC's public key");

        byte[] tampered = msg.clone();
        tampered[0] ^= 1;
        Signature joVerifier2 = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        joVerifier2.initVerify(sunKp.getPublic());
        joVerifier2.update(tampered);
        Assertions.assertFalse(joVerifier2.verify(sunSig),
                alg + ": JSL verified a tampered message");

        // Sign with JSL using SunEC's (foreign) private key, verify with SunEC.
        Signature joSigner = Signature.getInstance(alg, JostleProvider.PROVIDER_NAME);
        joSigner.initSign(sunKp.getPrivate());
        joSigner.update(msg);
        byte[] joSig = joSigner.sign();

        Signature sunVerifier = Signature.getInstance(alg, "SunEC");
        sunVerifier.initVerify(sunKp.getPublic());
        sunVerifier.update(msg);
        Assertions.assertTrue(sunVerifier.verify(joSig),
                alg + ": SunEC failed to verify a JSL signature made with SunEC's private key");

        // EdDSA is deterministic — signatures must match byte-for-byte.
        Assertions.assertArrayEquals(sunSig, joSig,
                alg + ": deterministic EdDSA signatures disagree between SunEC and JSL");
    }
}
