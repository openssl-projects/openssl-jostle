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

package org.openssl.jostle.test.dsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * DSA key-management tests: KeyPairGenerator, KeyFactory (encoded and
 * component-spec forms), AlgorithmParameters and
 * AlgorithmParameterGenerator, with BouncyCastle as the
 * cross-validation reference for every encoded form.
 *
 * <p>Tests favour 1024-bit parameters: DSA domain-parameter generation
 * is a prime search whose cost rises steeply with modulus size, and
 * {@code DSAKeyPairGenerator} caches parameters per size per JVM, so
 * the first 1024-bit test pays a sub-second cost and the rest reuse it.
 * One test exercises the 2048-bit default end-to-end.
 */
public class DSATest
{
    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same seed.
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
    public static void beforeAll()
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

    private static KeyPair generateKeyPair(int bits) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(bits);
        return kpg.generateKeyPair();
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator
    // -----------------------------------------------------------------

    @Test
    public void testKeyPairGen_1024_producesConsistentKey() throws Exception
    {
        KeyPair kp = generateKeyPair(1024);
        Assertions.assertTrue(kp.getPublic() instanceof DSAPublicKey);
        Assertions.assertTrue(kp.getPrivate() instanceof DSAPrivateKey);

        DSAPublicKey pub = (DSAPublicKey) kp.getPublic();
        DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();

        DSAParams params = pub.getParams();
        Assertions.assertNotNull(params, "getParams() must return real DSA parameters");
        Assertions.assertEquals(1024, params.getP().bitLength(), "p must be 1024 bits");
        Assertions.assertEquals(160, params.getQ().bitLength(), "q must be 160 bits");

        // The private half must report the same domain parameters.
        DSAParams privParams = priv.getParams();
        Assertions.assertEquals(params.getP(), privParams.getP());
        Assertions.assertEquals(params.getQ(), privParams.getQ());
        Assertions.assertEquals(params.getG(), privParams.getG());

        // Structural consistency: y == g^x mod p. An import path that
        // mangled a component (or a stub returning fixed bytes) fails this.
        BigInteger expectedY = params.getG().modPow(priv.getX(), params.getP());
        Assertions.assertEquals(expectedY, pub.getY(), "y must equal g^x mod p");

        // x must be in (0, q).
        Assertions.assertTrue(priv.getX().signum() > 0);
        Assertions.assertTrue(priv.getX().compareTo(params.getQ()) < 0,
                "x must be less than q");
    }

    @Test
    public void testKeyPairGen_2048_default() throws Exception
    {
        // 2048 is both an explicit size and the no-init default; this
        // covers the (2048, 256) parameter pairing end-to-end.
        KeyPair kp = generateKeyPair(2048);
        DSAPublicKey pub = (DSAPublicKey) kp.getPublic();
        Assertions.assertEquals(2048, pub.getParams().getP().bitLength());
        Assertions.assertEquals(256, pub.getParams().getQ().bitLength());

        // Sign/verify sanity on the larger parameters.
        byte[] msg = new byte[111];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testKeyPairGen_TwoKeysDiffer() throws Exception
    {
        // Domain parameters are cached per size, but the private value
        // must be fresh per generateKeyPair call.
        KeyPair a = generateKeyPair(1024);
        KeyPair b = generateKeyPair(1024);
        Assertions.assertNotEquals(((DSAPrivateKey) a.getPrivate()).getX(),
                ((DSAPrivateKey) b.getPrivate()).getX(),
                "two generated keys must have distinct private values");
        Assertions.assertFalse(Arrays.areEqual(a.getPublic().getEncoded(),
                        b.getPublic().getEncoded()),
                "two generated public keys must encode differently");
    }

    @Test
    public void testKeyPairGen_invalidSize_rejected() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        // Boundary probes around the supported set {1024, 2048, 3072}.
        for (int size : new int[]{0, 512, 1023, 1025, 2047, 2049, 3071, 3073, 4096})
        {
            try
            {
                kpg.initialize(size);
                Assertions.fail("expected InvalidParameterException for size " + size);
            }
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(
                        expected.getMessage().contains("DSA key size " + size),
                        "unexpected message: " + expected.getMessage());
            }
        }
    }

    @Test
    public void testKeyPairGen_nullSpec_rejected() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize((java.security.spec.AlgorithmParameterSpec) null);
            Assertions.fail("expected InvalidAlgorithmParameterException");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertEquals("AlgorithmParameterSpec is null", expected.getMessage());
        }
    }

    @Test
    public void testKeyPairGen_wrongSpecType_rejected() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
            Assertions.fail("expected InvalidAlgorithmParameterException");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("expected DSAParameterSpec"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void testKeyPairGen_explicitParams() throws Exception
    {
        // Derive parameters from a generated key, then generate a new
        // pair against those explicit parameters — the new key must
        // carry exactly the supplied (p, q, g).
        KeyPair seedKp = generateKeyPair(1024);
        DSAParams params = ((DSAPublicKey) seedKp.getPublic()).getParams();
        DSAParameterSpec spec = new DSAParameterSpec(
                params.getP(), params.getQ(), params.getG());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        DSAParams actual = ((DSAPublicKey) kp.getPublic()).getParams();
        Assertions.assertEquals(spec.getP(), actual.getP());
        Assertions.assertEquals(spec.getQ(), actual.getQ());
        Assertions.assertEquals(spec.getG(), actual.getG());

        // And the resulting key signs/verifies.
        byte[] msg = new byte[77];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }


    // -----------------------------------------------------------------
    // Encoded round-trips with BouncyCastle (both directions)
    // -----------------------------------------------------------------

    @Test
    public void testEncoded_JostleToBC_publicAndPrivate() throws Exception
    {
        KeyPair joKp = generateKeyPair(1024);

        KeyFactory bcKf = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);

        // Public: Jostle X.509 → BC decode → BC re-encode must be
        // byte-identical (catches OID / parameter mis-encoding that a
        // tolerant parser would otherwise hide).
        byte[] joPubEnc = joKp.getPublic().getEncoded();
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(joPubEnc));
        Assertions.assertTrue(bcPub instanceof DSAPublicKey);
        Assertions.assertArrayEquals(joPubEnc, bcPub.getEncoded(),
                "BC re-encoding of a Jostle DSA public key must be byte-identical");

        // Private: Jostle PKCS#8 → BC decode; compare components (BC's
        // PKCS#8 emission may legitimately differ in attribute details,
        // so compare x/p/q/g rather than bytes).
        byte[] joPrivEnc = joKp.getPrivate().getEncoded();
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(joPrivEnc));
        Assertions.assertTrue(bcPriv instanceof DSAPrivateKey);
        Assertions.assertEquals(((DSAPrivateKey) joKp.getPrivate()).getX(),
                ((DSAPrivateKey) bcPriv).getX());
        Assertions.assertEquals(((DSAPrivateKey) joKp.getPrivate()).getParams().getP(),
                ((DSAPrivateKey) bcPriv).getParams().getP());

        // The BC-decoded public key must verify a Jostle signature.
        byte[] msg = new byte[99];
        RANDOM.nextBytes(msg);
        Signature joSigner = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joKp.getPrivate());
        joSigner.update(msg);
        byte[] sig = joSigner.sign();
        Signature bcVerifier = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcPub);
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig));
    }

    @Test
    public void testEncoded_BCToJostle_publicAndPrivate() throws Exception
    {
        // BC generates the keypair on Jostle-produced parameters (fast,
        // avoids BC's own paramgen).
        KeyPair seedKp = generateKeyPair(1024);
        DSAParams params = ((DSAPublicKey) seedKp.getPublic()).getParams();

        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new DSAParameterSpec(params.getP(), params.getQ(), params.getG()));
        KeyPair bcKp = bcKpg.generateKeyPair();

        KeyFactory joKf = KeyFactory.getInstance("DSA", JostleProvider.PROVIDER_NAME);

        byte[] bcPubEnc = bcKp.getPublic().getEncoded();
        PublicKey joPub = joKf.generatePublic(new X509EncodedKeySpec(bcPubEnc));
        Assertions.assertTrue(joPub instanceof DSAPublicKey);
        Assertions.assertArrayEquals(bcPubEnc, joPub.getEncoded(),
                "Jostle re-encoding of a BC DSA public key must be byte-identical");

        byte[] bcPrivEnc = bcKp.getPrivate().getEncoded();
        PrivateKey joPriv = joKf.generatePrivate(new PKCS8EncodedKeySpec(bcPrivEnc));
        Assertions.assertTrue(joPriv instanceof DSAPrivateKey);
        Assertions.assertEquals(((DSAPrivateKey) bcKp.getPrivate()).getX(),
                ((DSAPrivateKey) joPriv).getX());

        // The Jostle-decoded private key must produce a signature BC accepts.
        byte[] msg = new byte[123];
        RANDOM.nextBytes(msg);
        Signature joSigner = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        joSigner.initSign(joPriv);
        joSigner.update(msg);
        byte[] sig = joSigner.sign();
        Signature bcVerifier = Signature.getInstance("SHA256withDSA", BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcKp.getPublic());
        bcVerifier.update(msg);
        Assertions.assertTrue(bcVerifier.verify(sig));
    }


    // -----------------------------------------------------------------
    // Component-spec forms (DSAPublicKeySpec / DSAPrivateKeySpec)
    // -----------------------------------------------------------------

    @Test
    public void testKeyFactory_publicComponentSpec_roundTrip() throws Exception
    {
        KeyPair kp = generateKeyPair(1024);
        DSAPublicKey pub = (DSAPublicKey) kp.getPublic();
        DSAParams params = pub.getParams();

        KeyFactory kf = KeyFactory.getInstance("DSA", JostleProvider.PROVIDER_NAME);

        // getKeySpec → generatePublic must reproduce the same key.
        DSAPublicKeySpec spec = kf.getKeySpec(pub, DSAPublicKeySpec.class);
        Assertions.assertEquals(pub.getY(), spec.getY());
        Assertions.assertEquals(params.getP(), spec.getP());

        PublicKey rebuilt = kf.generatePublic(spec);
        Assertions.assertArrayEquals(pub.getEncoded(), rebuilt.getEncoded(),
                "component-rebuilt public key must encode identically");
    }

    @Test
    public void testKeyFactory_privateComponentSpec_roundTrip() throws Exception
    {
        KeyPair kp = generateKeyPair(1024);
        DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();

        KeyFactory kf = KeyFactory.getInstance("DSA", JostleProvider.PROVIDER_NAME);

        DSAPrivateKeySpec spec = kf.getKeySpec(priv, DSAPrivateKeySpec.class);
        Assertions.assertEquals(priv.getX(), spec.getX());

        PrivateKey rebuilt = kf.generatePrivate(spec);
        Assertions.assertEquals(priv.getX(), ((DSAPrivateKey) rebuilt).getX());

        // The rebuilt private key must sign something the original
        // public key verifies — proves y was correctly re-derived from
        // x on the native side.
        byte[] msg = new byte[88];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(rebuilt);
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "signature from component-rebuilt private key must verify "
                        + "against the original public key");
    }

    @Test
    public void testKeyFactory_rejectsForeignAlgorithmEncoding() throws Exception
    {
        // An RSA SPKI handed to the DSA KeyFactory must be rejected
        // with a typed InvalidKeySpecException naming the mismatch.
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(rsa.getPublic().getEncoded()));
            Assertions.fail("expected InvalidKeySpecException");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertEquals("expected DSA key but got RSA", expected.getMessage());
        }
    }

    @Test
    public void testKeyFactory_translateForeignKey() throws Exception
    {
        // A SUN-provider DSA key must translate into a usable Jostle key.
        KeyPairGenerator sunKpg = KeyPairGenerator.getInstance("DSA", "SUN");
        sunKpg.initialize(1024);
        KeyPair sunKp = sunKpg.generateKeyPair();

        KeyFactory joKf = KeyFactory.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        PrivateKey joPriv = (PrivateKey) joKf.translateKey(sunKp.getPrivate());
        PublicKey joPub = (PublicKey) joKf.translateKey(sunKp.getPublic());

        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(joPriv);
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(joPub);
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig),
                "translated SUN DSA keypair must sign/verify through Jostle");
    }


    // -----------------------------------------------------------------
    // AlgorithmParameters / AlgorithmParameterGenerator
    // -----------------------------------------------------------------

    @Test
    public void testAlgorithmParameters_encodeDecodeAgainstBC() throws Exception
    {
        KeyPair kp = generateKeyPair(1024);
        DSAParams params = ((DSAPublicKey) kp.getPublic()).getParams();
        DSAParameterSpec spec = new DSAParameterSpec(
                params.getP(), params.getQ(), params.getG());

        // Jostle encode → BC decode.
        AlgorithmParameters joParams = AlgorithmParameters.getInstance(
                "DSA", JostleProvider.PROVIDER_NAME);
        joParams.init(spec);
        byte[] der = joParams.getEncoded();

        AlgorithmParameters bcParams = AlgorithmParameters.getInstance(
                "DSA", BouncyCastleProvider.PROVIDER_NAME);
        bcParams.init(der);
        DSAParameterSpec bcSpec = bcParams.getParameterSpec(DSAParameterSpec.class);
        Assertions.assertEquals(spec.getP(), bcSpec.getP());
        Assertions.assertEquals(spec.getQ(), bcSpec.getQ());
        Assertions.assertEquals(spec.getG(), bcSpec.getG());

        // BC encode → Jostle decode.
        byte[] bcDer = bcParams.getEncoded();
        AlgorithmParameters joDecoded = AlgorithmParameters.getInstance(
                "DSA", JostleProvider.PROVIDER_NAME);
        joDecoded.init(bcDer);
        DSAParameterSpec joSpec = joDecoded.getParameterSpec(DSAParameterSpec.class);
        Assertions.assertEquals(spec.getP(), joSpec.getP());
        Assertions.assertEquals(spec.getQ(), joSpec.getQ());
        Assertions.assertEquals(spec.getG(), joSpec.getG());
    }

    @Test
    public void testAlgorithmParameterGenerator_generatesUsableParams() throws Exception
    {
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(
                "DSA", JostleProvider.PROVIDER_NAME);
        apg.init(1024, RANDOM);
        AlgorithmParameters params = apg.generateParameters();

        DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);
        Assertions.assertEquals(1024, spec.getP().bitLength());
        Assertions.assertEquals(160, spec.getQ().bitLength());
        // g must be a generator of the q-order subgroup: g^q mod p == 1
        // and g != 1.
        Assertions.assertNotEquals(BigInteger.ONE, spec.getG());
        Assertions.assertEquals(BigInteger.ONE,
                spec.getG().modPow(spec.getQ(), spec.getP()),
                "g^q mod p must be 1 (g generates the q-order subgroup)");
        // p must be odd (trivially true for a prime > 2) and q must
        // divide p - 1.
        Assertions.assertEquals(BigInteger.ZERO,
                spec.getP().subtract(BigInteger.ONE).mod(spec.getQ()),
                "q must divide p - 1");

        // The generated parameters must drive a working keypair.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", JostleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();
        byte[] msg = new byte[55];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("SHA1withDSA", JostleProvider.PROVIDER_NAME);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("SHA1withDSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));
    }

    @Test
    public void testAlgorithmParameterGenerator_invalidSize_rejected() throws Exception
    {
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(
                "DSA", JostleProvider.PROVIDER_NAME);
        for (int size : new int[]{0, 512, 1023, 2047, 3073})
        {
            try
            {
                apg.init(size, RANDOM);
                Assertions.fail("expected InvalidParameterException for size " + size);
            }
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(
                        expected.getMessage().contains("DSA parameter size " + size),
                        "unexpected message: " + expected.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    @Test
    public void testGetInstanceByOID_keyFactoryAndKpg() throws Exception
    {
        // id-dsa = 1.2.840.10040.4.1 must resolve for KeyFactory,
        // KeyPairGenerator and AlgorithmParameters.
        Assertions.assertNotNull(KeyFactory.getInstance(
                "1.2.840.10040.4.1", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(KeyPairGenerator.getInstance(
                "1.2.840.10040.4.1", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(AlgorithmParameters.getInstance(
                "1.2.840.10040.4.1", JostleProvider.PROVIDER_NAME));
    }

    @Test
    public void testKeyAlgorithmAndFormats() throws Exception
    {
        KeyPair kp = generateKeyPair(1024);
        Assertions.assertEquals("DSA", kp.getPublic().getAlgorithm());
        Assertions.assertEquals("DSA", kp.getPrivate().getAlgorithm());
        Assertions.assertEquals("X.509", kp.getPublic().getFormat());
        Assertions.assertEquals("PKCS#8", kp.getPrivate().getFormat());
    }
}
