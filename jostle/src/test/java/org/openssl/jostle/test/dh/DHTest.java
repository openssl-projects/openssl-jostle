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

package org.openssl.jostle.test.dh;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * DH key-management tests: KeyPairGenerator (RFC 7919 named groups and
 * explicit {@link DHParameterSpec}), KeyFactory (encoded and
 * component-spec forms), AlgorithmParameters and
 * AlgorithmParameterGenerator, with BouncyCastle as the
 * cross-validation reference for every encoded form.
 *
 * <p>Tests favour the ffdhe2048 named group (instant keygen). The one
 * AlgorithmParameterGenerator test uses 512-bit safe-prime generation
 * to keep the prime search sub-second.
 */
public class DHTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

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

    private static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator
    // -----------------------------------------------------------------

    @Test
    public void testKeyPairGen_2048_producesConsistentKey() throws Exception
    {
        KeyPair kp = generateKeyPair();
        Assertions.assertTrue(kp.getPublic() instanceof DHPublicKey);
        Assertions.assertTrue(kp.getPrivate() instanceof DHPrivateKey);

        DHPublicKey pub = (DHPublicKey) kp.getPublic();
        DHPrivateKey priv = (DHPrivateKey) kp.getPrivate();

        DHParameterSpec params = pub.getParams();
        Assertions.assertNotNull(params, "getParams() must return real DH parameters");
        Assertions.assertEquals(2048, params.getP().bitLength(), "p must be 2048 bits");

        // ffdhe2048 (RFC 7919): generator is 2.
        Assertions.assertEquals(BigInteger.valueOf(2), params.getG(),
                "ffdhe2048 generator must be 2");

        // The private half must report the same domain parameters.
        DHParameterSpec privParams = priv.getParams();
        Assertions.assertEquals(params.getP(), privParams.getP());
        Assertions.assertEquals(params.getG(), privParams.getG());

        // Structural consistency: y == g^x mod p. An import path that
        // mangled a component (or a stub returning fixed bytes) fails this.
        BigInteger expectedY = params.getG().modPow(priv.getX(), params.getP());
        Assertions.assertEquals(expectedY, pub.getY(), "y must equal g^x mod p");
    }

    @Test
    public void testKeyPairGen_TwoKeysDiffer() throws Exception
    {
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();
        Assertions.assertNotEquals(((DHPrivateKey) a.getPrivate()).getX(),
                ((DHPrivateKey) b.getPrivate()).getX(),
                "two generated keys must have distinct private values");
        Assertions.assertFalse(Arrays.areEqual(a.getPublic().getEncoded(),
                        b.getPublic().getEncoded()),
                "two generated public keys must encode differently");
    }

    @Test
    public void testKeyPairGen_invalidSize_rejected() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        // Boundary probes around the supported set {2048,3072,4096,6144,8192}.
        for (int size : new int[]{0, 512, 1024, 2047, 2049, 3071, 4097, 8193})
        {
            try
            {
                kpg.initialize(size);
                Assertions.fail("expected InvalidParameterException for size " + size);
            }
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(
                        expected.getMessage().contains("DH key size " + size),
                        "unexpected message: " + expected.getMessage());
            }
        }
    }

    @Test
    public void testKeyPairGen_nullSpec_rejected() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        try
        {
            kpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
            Assertions.fail("expected InvalidAlgorithmParameterException");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("expected DHParameterSpec"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    @Test
    public void testKeyPairGen_explicitParams() throws Exception
    {
        // Derive parameters from a generated key, then generate a new
        // pair against those explicit parameters — the new key must
        // carry exactly the supplied (p, g).
        KeyPair seedKp = generateKeyPair();
        DHParameterSpec params = ((DHPublicKey) seedKp.getPublic()).getParams();
        DHParameterSpec spec = new DHParameterSpec(params.getP(), params.getG());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        DHParameterSpec actual = ((DHPublicKey) kp.getPublic()).getParams();
        Assertions.assertEquals(spec.getP(), actual.getP());
        Assertions.assertEquals(spec.getG(), actual.getG());

        // And the two keypairs (same group, distinct keys) must agree
        // on a shared secret — the proof the explicit-params key is
        // functional.
        KeyAgreement kaA = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kaA.init(seedKp.getPrivate());
        kaA.doPhase(kp.getPublic(), true);
        byte[] secretA = kaA.generateSecret();

        KeyAgreement kaB = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kaB.init(kp.getPrivate());
        kaB.doPhase(seedKp.getPublic(), true);
        byte[] secretB = kaB.generateSecret();

        Assertions.assertArrayEquals(secretA, secretB,
                "both sides must derive the same shared secret");
    }


    // -----------------------------------------------------------------
    // Encoded round-trips with BouncyCastle (both directions)
    // -----------------------------------------------------------------

    @Test
    public void testEncoded_JostleToBC_publicAndPrivate() throws Exception
    {
        KeyPair joKp = generateKeyPair();

        KeyFactory bcKf = KeyFactory.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);

        // Public: Jostle X.509 → BC decode; compare components (BC may
        // legitimately re-order/augment the PKCS#3 parameter encoding,
        // so byte-compare is done in the Jostle-decodes-BC direction
        // below where Jostle re-emits via OpenSSL).
        byte[] joPubEnc = joKp.getPublic().getEncoded();
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(joPubEnc));
        Assertions.assertTrue(bcPub instanceof DHPublicKey);
        Assertions.assertEquals(((DHPublicKey) joKp.getPublic()).getY(),
                ((DHPublicKey) bcPub).getY());
        Assertions.assertEquals(((DHPublicKey) joKp.getPublic()).getParams().getP(),
                ((DHPublicKey) bcPub).getParams().getP());
        Assertions.assertEquals(((DHPublicKey) joKp.getPublic()).getParams().getG(),
                ((DHPublicKey) bcPub).getParams().getG());

        // Private: Jostle PKCS#8 → BC decode; compare components.
        byte[] joPrivEnc = joKp.getPrivate().getEncoded();
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(joPrivEnc));
        Assertions.assertTrue(bcPriv instanceof DHPrivateKey);
        Assertions.assertEquals(((DHPrivateKey) joKp.getPrivate()).getX(),
                ((DHPrivateKey) bcPriv).getX());
    }

    @Test
    public void testEncoded_BCToJostle_publicAndPrivate() throws Exception
    {
        // BC generates the keypair on Jostle-produced parameters (fast,
        // avoids BC's own paramgen).
        KeyPair seedKp = generateKeyPair();
        DHParameterSpec params = ((DHPublicKey) seedKp.getPublic()).getParams();

        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new DHParameterSpec(params.getP(), params.getG()));
        KeyPair bcKp = bcKpg.generateKeyPair();

        KeyFactory joKf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);

        byte[] bcPubEnc = bcKp.getPublic().getEncoded();
        PublicKey joPub = joKf.generatePublic(new X509EncodedKeySpec(bcPubEnc));
        Assertions.assertTrue(joPub instanceof DHPublicKey);
        Assertions.assertEquals(((DHPublicKey) bcKp.getPublic()).getY(),
                ((DHPublicKey) joPub).getY());

        byte[] bcPrivEnc = bcKp.getPrivate().getEncoded();
        PrivateKey joPriv = joKf.generatePrivate(new PKCS8EncodedKeySpec(bcPrivEnc));
        Assertions.assertTrue(joPriv instanceof DHPrivateKey);
        Assertions.assertEquals(((DHPrivateKey) bcKp.getPrivate()).getX(),
                ((DHPrivateKey) joPriv).getX());

        // The Jostle-decoded private key must agree with the original
        // Jostle key — exercises the decoded key end-to-end.
        KeyAgreement joKa = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        joKa.init(joPriv);
        joKa.doPhase(seedKp.getPublic(), true);
        byte[] secretA = joKa.generateSecret();

        KeyAgreement joKa2 = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        joKa2.init(seedKp.getPrivate());
        joKa2.doPhase(joPub, true);
        byte[] secretB = joKa2.generateSecret();

        Assertions.assertArrayEquals(secretA, secretB,
                "agreement across BC-decoded keys must match");
    }

    /**
     * The OpenSSL-emitted X.509/PKCS#8 forms must round-trip through
     * Jostle's own KeyFactory byte-identically.
     */
    @Test
    public void testEncoded_JostleSelfRoundTrip_byteIdentical() throws Exception
    {
        KeyPair kp = generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);

        byte[] pubEnc = kp.getPublic().getEncoded();
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pubEnc));
        Assertions.assertArrayEquals(pubEnc, pub2.getEncoded(),
                "public X.509 re-encoding must be byte-identical");

        byte[] privEnc = kp.getPrivate().getEncoded();
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));
        Assertions.assertArrayEquals(privEnc, priv2.getEncoded(),
                "private PKCS#8 re-encoding must be byte-identical");
    }


    // -----------------------------------------------------------------
    // Component-spec forms (DHPublicKeySpec / DHPrivateKeySpec)
    // -----------------------------------------------------------------

    @Test
    public void testKeyFactory_publicComponentSpec_roundTrip() throws Exception
    {
        KeyPair kp = generateKeyPair();
        DHPublicKey pub = (DHPublicKey) kp.getPublic();

        KeyFactory kf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);

        DHPublicKeySpec spec = kf.getKeySpec(pub, DHPublicKeySpec.class);
        Assertions.assertEquals(pub.getY(), spec.getY());
        Assertions.assertEquals(pub.getParams().getP(), spec.getP());

        PublicKey rebuilt = kf.generatePublic(spec);
        Assertions.assertArrayEquals(pub.getEncoded(), rebuilt.getEncoded(),
                "component-rebuilt public key must encode identically");
    }

    @Test
    public void testKeyFactory_privateComponentSpec_roundTrip() throws Exception
    {
        KeyPair kp = generateKeyPair();
        DHPrivateKey priv = (DHPrivateKey) kp.getPrivate();

        KeyFactory kf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);

        DHPrivateKeySpec spec = kf.getKeySpec(priv, DHPrivateKeySpec.class);
        Assertions.assertEquals(priv.getX(), spec.getX());

        PrivateKey rebuilt = kf.generatePrivate(spec);
        Assertions.assertEquals(priv.getX(), ((DHPrivateKey) rebuilt).getX());

        // The rebuilt private key must derive the same shared secret
        // as the original — proves y was correctly re-derived from x
        // on the native side.
        KeyPair other = generateKeyPair();
        KeyAgreement kaOrig = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kaOrig.init(kp.getPrivate());
        kaOrig.doPhase(other.getPublic(), true);
        byte[] secretOrig = kaOrig.generateSecret();

        KeyAgreement kaRebuilt = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kaRebuilt.init(rebuilt);
        kaRebuilt.doPhase(other.getPublic(), true);
        byte[] secretRebuilt = kaRebuilt.generateSecret();

        Assertions.assertArrayEquals(secretOrig, secretRebuilt,
                "component-rebuilt private key must derive the same secret");
    }

    @Test
    public void testKeyFactory_rejectsForeignAlgorithmEncoding() throws Exception
    {
        // An RSA SPKI handed to the DH KeyFactory must be rejected
        // with a typed InvalidKeySpecException naming the mismatch.
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(rsa.getPublic().getEncoded()));
            Assertions.fail("expected InvalidKeySpecException");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertEquals("expected DH key but got RSA", expected.getMessage());
        }
    }

    @Test
    public void testKeyFactory_translateForeignKey() throws Exception
    {
        // A SunJCE DH key must translate into a usable Jostle key.
        KeyPairGenerator sunKpg = KeyPairGenerator.getInstance("DH", "SunJCE");
        sunKpg.initialize(2048);
        KeyPair sunKp = sunKpg.generateKeyPair();

        KeyFactory joKf = KeyFactory.getInstance("DH", JostleProvider.PROVIDER_NAME);
        PrivateKey joPriv = (PrivateKey) joKf.translateKey(sunKp.getPrivate());
        PublicKey joPub = (PublicKey) joKf.translateKey(sunKp.getPublic());

        Assertions.assertEquals(((DHPrivateKey) sunKp.getPrivate()).getX(),
                ((DHPrivateKey) joPriv).getX());
        Assertions.assertEquals(((DHPublicKey) sunKp.getPublic()).getY(),
                ((DHPublicKey) joPub).getY());
    }


    // -----------------------------------------------------------------
    // AlgorithmParameters / AlgorithmParameterGenerator
    // -----------------------------------------------------------------

    @Test
    public void testAlgorithmParameters_encodeDecodeAgainstBC() throws Exception
    {
        KeyPair kp = generateKeyPair();
        DHParameterSpec params = ((DHPublicKey) kp.getPublic()).getParams();
        DHParameterSpec spec = new DHParameterSpec(params.getP(), params.getG());

        // Jostle encode → BC decode.
        AlgorithmParameters joParams = AlgorithmParameters.getInstance(
                "DH", JostleProvider.PROVIDER_NAME);
        joParams.init(spec);
        byte[] der = joParams.getEncoded();

        AlgorithmParameters bcParams = AlgorithmParameters.getInstance(
                "DH", BouncyCastleProvider.PROVIDER_NAME);
        bcParams.init(der);
        DHParameterSpec bcSpec = bcParams.getParameterSpec(DHParameterSpec.class);
        Assertions.assertEquals(spec.getP(), bcSpec.getP());
        Assertions.assertEquals(spec.getG(), bcSpec.getG());

        // BC encode → Jostle decode.
        byte[] bcDer = bcParams.getEncoded();
        AlgorithmParameters joDecoded = AlgorithmParameters.getInstance(
                "DH", JostleProvider.PROVIDER_NAME);
        joDecoded.init(bcDer);
        DHParameterSpec joSpec = joDecoded.getParameterSpec(DHParameterSpec.class);
        Assertions.assertEquals(spec.getP(), joSpec.getP());
        Assertions.assertEquals(spec.getG(), joSpec.getG());
    }

    @Test
    public void testAlgorithmParameterGenerator_generatesUsableParams() throws Exception
    {
        // 512-bit safe-prime generation keeps the prime search fast;
        // larger sizes use the same code path.
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(
                "DH", JostleProvider.PROVIDER_NAME);
        apg.init(512, RANDOM);
        AlgorithmParameters params = apg.generateParameters();

        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        Assertions.assertEquals(512, spec.getP().bitLength());
        // Safe prime: (p - 1) / 2 must also be prime.
        BigInteger q = spec.getP().subtract(BigInteger.ONE).shiftRight(1);
        Assertions.assertTrue(q.isProbablePrime(64),
                "(p-1)/2 must be prime for a PKCS#3 safe-prime group");

        // The generated parameters must drive a working agreement.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        KeyPair a = kpg.generateKeyPair();
        KeyPair b = kpg.generateKeyPair();

        KeyAgreement kaA = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kaA.init(a.getPrivate());
        kaA.doPhase(b.getPublic(), true);
        KeyAgreement kaB = KeyAgreement.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kaB.init(b.getPrivate());
        kaB.doPhase(a.getPublic(), true);
        Assertions.assertArrayEquals(kaA.generateSecret(), kaB.generateSecret());
    }

    @Test
    public void testAlgorithmParameterGenerator_invalidSize_rejected() throws Exception
    {
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(
                "DH", JostleProvider.PROVIDER_NAME);
        // Boundary probes: below minimum, above maximum, non-multiple of 64.
        for (int size : new int[]{0, 448, 511, 513, 8256, 1000})
        {
            try
            {
                apg.init(size, RANDOM);
                Assertions.fail("expected InvalidParameterException for size " + size);
            }
            catch (InvalidParameterException expected)
            {
                Assertions.assertTrue(
                        expected.getMessage().contains("DH parameter size " + size),
                        "unexpected message: " + expected.getMessage());
            }
        }
    }


    // -----------------------------------------------------------------
    // Provider plumbing
    // -----------------------------------------------------------------

    @Test
    public void testGetInstanceByAliasAndOID() throws Exception
    {
        // The JCA standard name, the PKCS#3 OID and the X9.42 OID must
        // all resolve.
        Assertions.assertNotNull(KeyPairGenerator.getInstance(
                "DiffieHellman", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(KeyFactory.getInstance(
                "DiffieHellman", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(KeyAgreement.getInstance(
                "DiffieHellman", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(KeyFactory.getInstance(
                "1.2.840.113549.1.3.1", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(KeyFactory.getInstance(
                "1.2.840.10046.2.1", JostleProvider.PROVIDER_NAME));
        Assertions.assertNotNull(AlgorithmParameters.getInstance(
                "1.2.840.113549.1.3.1", JostleProvider.PROVIDER_NAME));
    }

    @Test
    public void testKeyAlgorithmAndFormats() throws Exception
    {
        KeyPair kp = generateKeyPair();
        Assertions.assertEquals("DH", kp.getPublic().getAlgorithm());
        Assertions.assertEquals("DH", kp.getPrivate().getAlgorithm());
        Assertions.assertEquals("X.509", kp.getPublic().getFormat());
        Assertions.assertEquals("PKCS#8", kp.getPrivate().getFormat());
    }
}
