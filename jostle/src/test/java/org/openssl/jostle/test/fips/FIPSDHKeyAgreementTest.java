/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHPrivateKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * JCE-level behaviour locks for the FIPS provider's DH KeyAgreement surface —
 * the FIPS analogue of {@code dh/DHKeyAgreementTest} (and the DH arms of
 * {@code dh/DHTest}). Covers foreign-key rejection at init and doPhase,
 * state-machine guards, the {@code generateSecret(byte[], int)} offset/
 * ShortBuffer contract, group-mismatch rejection, KeyPairGenerator size
 * rejection, the KeyFactory foreign-algorithm / malformed-DER contract,
 * OID/alias resolution, post-terminal reuse, and {@code generateSecret(String)}.
 * <p>
 * The DHKeyAgreementSpi / DHKeyFactorySpi / DHKeyPairGenerator are shared with
 * the non-FIPS provider, so the exception types and messages match the non-FIPS
 * reference exactly; only the provider name, gating, and key origin change here.
 * <p>
 * KEY ORIGIN: all DH and RSA keypairs are generated through the FIPS provider
 * so the operational keys are provider-consistent. The domain group is RFC 7919
 * ffdhe2048 ({@code initialize(2048)}, a FIPS-approved safe-prime group), so
 * keygen is instant; the group-mismatch test also uses ffdhe3072
 * ({@code initialize(3072)}). Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSDHKeyAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    private static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", FIPS);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static byte[] agree(PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DH", FIPS);
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }


    // -----------------------------------------------------------------
    // Wrong-key rejection: InvalidKeyException at init and doPhase
    // -----------------------------------------------------------------

    @Test
    public void dhKeyAgreementRejectsForeignKey_throwsInvalidKeyException() throws Exception
    {
        ensureProviders();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", FIPS);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        // init with a foreign (RSA) private key -> InvalidKeyException.
        KeyAgreement kaInit = KeyAgreement.getInstance("DH", FIPS);
        try
        {
            kaInit.init(rsa.getPrivate());
            Assertions.fail("expected InvalidKeyException for RSA private key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("DH init: expected a DHPrivateKey", expected.getMessage());
        }

        // doPhase with a foreign (RSA) public key after a valid init.
        KeyPair dh = generateKeyPair();
        KeyAgreement kaPhase = KeyAgreement.getInstance("DH", FIPS);
        kaPhase.init(dh.getPrivate());
        try
        {
            kaPhase.doPhase(rsa.getPublic(), true);
            Assertions.fail("expected InvalidKeyException for RSA public key");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals("DH doPhase: expected a DHPublicKey", expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // State-machine guards
    // -----------------------------------------------------------------

    @Test
    public void dhKeyAgreementStateMachineGuards_throwIllegalState() throws Exception
    {
        ensureProviders();

        // generateSecret before doPhase.
        KeyPair kp = generateKeyPair();
        KeyAgreement kaNoPhase = KeyAgreement.getInstance("DH", FIPS);
        kaNoPhase.init(kp.getPrivate());
        try
        {
            kaNoPhase.generateSecret();
            Assertions.fail("generateSecret before doPhase must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals("DH: must call doPhase before generateSecret",
                    expected.getMessage());
        }

        // doPhase(peer, false): DH here is single-phase.
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();
        KeyAgreement kaNotLast = KeyAgreement.getInstance("DH", FIPS);
        kaNotLast.init(a.getPrivate());
        try
        {
            kaNotLast.doPhase(b.getPublic(), false);
            Assertions.fail("lastPhase=false must throw");
        }
        catch (IllegalStateException expected)
        {
            Assertions.assertEquals(
                    "DH is a single-phase protocol here; lastPhase must be true",
                    expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // generateSecret(byte[], int) offset contract + ShortBuffer
    // -----------------------------------------------------------------

    @Test
    public void dhGenerateSecretAtOffset_prefixUntouchedAndShortBufferRejected() throws Exception
    {
        ensureProviders();

        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        // Reference secret via the allocating form.
        byte[] expected = agree(a.getPrivate(), b.getPublic());

        KeyAgreement ka = KeyAgreement.getInstance("DH", FIPS);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);

        int prefix = 7;
        byte[] big = new byte[prefix + expected.length + 5];
        RANDOM.nextBytes(big);
        byte[] expectedPrefix = new byte[prefix];
        System.arraycopy(big, 0, expectedPrefix, 0, prefix);

        int written = ka.generateSecret(big, prefix);
        Assertions.assertEquals(expected.length, written);

        // (1) Prefix untouched.
        byte[] actualPrefix = new byte[prefix];
        System.arraycopy(big, 0, actualPrefix, 0, prefix);
        Assertions.assertArrayEquals(expectedPrefix, actualPrefix,
                "generateSecret modified bytes preceding the offset");

        // (2) Functional check: the window at the offset is the secret.
        byte[] window = new byte[written];
        System.arraycopy(big, prefix, window, 0, written);
        Assertions.assertArrayEquals(expected, window,
                "secret at offset must equal the allocating-form secret");

        // (3) A window shifted one byte into the prefix must differ.
        byte[] shifted = new byte[written];
        System.arraycopy(big, prefix - 1, shifted, 0, written);
        Assertions.assertFalse(Arrays.areEqual(expected, shifted),
                "window shifted by 1 matched — wrote at offset-1");

        // ShortBufferException: secret is 256 bytes (2048-bit p); a buffer one
        // byte short from the offset must be rejected.
        KeyAgreement kaShort = KeyAgreement.getInstance("DH", FIPS);
        kaShort.init(a.getPrivate());
        kaShort.doPhase(b.getPublic(), true);
        byte[] small = new byte[256];
        try
        {
            kaShort.generateSecret(small, 1);
            Assertions.fail("expected ShortBufferException");
        }
        catch (ShortBufferException expected2)
        {
            Assertions.assertTrue(
                    expected2.getMessage().startsWith("DH generateSecret: buffer needs"),
                    "unexpected message: " + expected2.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Group-mismatch rejection at doPhase
    // -----------------------------------------------------------------

    @Test
    public void dhGroupMismatch_rejectedAtDoPhase_throwsInvalidKeyException() throws Exception
    {
        ensureProviders();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", FIPS);
        kpg.initialize(2048);
        KeyPair k2048 = kpg.generateKeyPair();
        kpg.initialize(3072);
        KeyPair k3072 = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", FIPS);
        ka.init(k2048.getPrivate());
        try
        {
            ka.doPhase(k3072.getPublic(), true);
            Assertions.fail("expected InvalidKeyException for group mismatch");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("DH doPhase: peer key rejected"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // KeyPairGenerator size rejection
    // -----------------------------------------------------------------

    @Test
    public void dhKeyPairGeneratorRejectsInvalidSize() throws Exception
    {
        ensureProviders();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", FIPS);
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


    // -----------------------------------------------------------------
    // KeyFactory: foreign-algorithm and malformed-DER rejection
    // -----------------------------------------------------------------

    @Test
    public void keyFactoryRejectsForeignAlgorithmAndMalformedDer() throws Exception
    {
        ensureProviders();

        // An RSA SPKI handed to the DH KeyFactory must be rejected with a typed
        // InvalidKeySpecException naming the mismatch.
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", FIPS);
        rsaKpg.initialize(2048);
        KeyPair rsa = rsaKpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("DH", FIPS);
        try
        {
            kf.generatePublic(new X509EncodedKeySpec(rsa.getPublic().getEncoded()));
            Assertions.fail("expected InvalidKeySpecException");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertEquals("expected DH key but got RSA", expected.getMessage());
        }

        // Malformed DER must surface as the checked InvalidKeySpecException, not
        // an unchecked OpenSSLException.
        byte[] garbage = new byte[40];
        RANDOM.nextBytes(garbage);
        byte[] truncated = {0x30, (byte) 0x82, 0x04, 0x00, 0x02, 0x01, 0x00}; // SEQUENCE claims 1024 bytes

        for (byte[] bad : new byte[][]{garbage, truncated})
        {
            InvalidKeySpecException pub = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new X509EncodedKeySpec(bad)),
                    "malformed SPKI must throw InvalidKeySpecException");
            Assertions.assertTrue(pub.getMessage().startsWith("unable to decode DH public key"),
                    "unexpected message: " + pub.getMessage());

            InvalidKeySpecException priv = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new PKCS8EncodedKeySpec(bad)),
                    "malformed PKCS#8 must throw InvalidKeySpecException");
            Assertions.assertTrue(priv.getMessage().startsWith("unable to decode DH private key"),
                    "unexpected message: " + priv.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // OID / alias resolution
    // -----------------------------------------------------------------

    @Test
    public void dsaAndDhOidAliasesResolveThroughJslfips() throws Exception
    {
        ensureProviders();

        // The JCA standard name, the "DiffieHellman" alias, the PKCS#3 OID and
        // the X9.42 OID must all resolve through JSLFIPS.
        Assertions.assertNotNull(KeyPairGenerator.getInstance("DiffieHellman", FIPS));
        Assertions.assertNotNull(KeyFactory.getInstance("DiffieHellman", FIPS));
        Assertions.assertNotNull(KeyAgreement.getInstance("DiffieHellman", FIPS));

        Assertions.assertNotNull(KeyPairGenerator.getInstance("1.2.840.113549.1.3.1", FIPS));
        Assertions.assertNotNull(KeyFactory.getInstance("1.2.840.113549.1.3.1", FIPS));
        Assertions.assertNotNull(KeyAgreement.getInstance("1.2.840.113549.1.3.1", FIPS));
        Assertions.assertNotNull(AlgorithmParameters.getInstance("1.2.840.113549.1.3.1", FIPS));

        Assertions.assertNotNull(KeyPairGenerator.getInstance("1.2.840.10046.2.1", FIPS));
        Assertions.assertNotNull(KeyFactory.getInstance("1.2.840.10046.2.1", FIPS));

        // The RFC 2631 DH-KDF KeyAgreement resolves by name and by the ESDH /
        // SSDH OID aliases.
        Assertions.assertNotNull(KeyAgreement.getInstance("DHWITHRFC2631KDF", FIPS));
        Assertions.assertNotNull(KeyAgreement.getInstance(
                "1.2.840.113549.1.9.16.3.5", FIPS));  // id-alg-ESDH
        Assertions.assertNotNull(KeyAgreement.getInstance(
                "1.2.840.113549.1.9.16.3.10", FIPS)); // id-alg-SSDH
    }


    // -----------------------------------------------------------------
    // Post-terminal reuse
    // -----------------------------------------------------------------

    @Test
    public void dhReuseAfterGenerateSecret_tracksNewPeer() throws Exception
    {
        ensureProviders();

        // JCE contract: generateSecret resets the KA to its post-init state; a
        // fresh doPhase against a different peer must work and change the secret.
        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();
        KeyPair c = generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", FIPS);
        ka.init(a.getPrivate());

        ka.doPhase(b.getPublic(), true);
        byte[] secretAB = ka.generateSecret();
        Assertions.assertArrayEquals(
                agree(b.getPrivate(), a.getPublic()),
                secretAB);

        ka.doPhase(c.getPublic(), true);
        byte[] secretAC = ka.generateSecret();
        Assertions.assertArrayEquals(
                agree(c.getPrivate(), a.getPublic()),
                secretAC);

        Assertions.assertFalse(Arrays.areEqual(secretAB, secretAC),
                "reused KeyAgreement must track the new peer");
    }


    // -----------------------------------------------------------------
    // generateSecret(String): named algorithm + blank rejection
    // -----------------------------------------------------------------

    @Test
    public void dhGenerateSecretNamedAndBlankAlgorithm() throws Exception
    {
        ensureProviders();

        KeyPair a = generateKeyPair();
        KeyPair b = generateKeyPair();

        // Named algorithm: right algorithm + p-length (256 bytes for ffdhe2048).
        KeyAgreement kaNamed = KeyAgreement.getInstance("DH", FIPS);
        kaNamed.init(a.getPrivate());
        kaNamed.doPhase(b.getPublic(), true);
        SecretKey key = kaNamed.generateSecret("TlsPremasterSecret");
        Assertions.assertEquals("TlsPremasterSecret", key.getAlgorithm());
        Assertions.assertEquals(256, key.getEncoded().length);

        // Blank name: NoSuchAlgorithmException with the fixed message.
        KeyAgreement kaBlank = KeyAgreement.getInstance("DH", FIPS);
        kaBlank.init(a.getPrivate());
        kaBlank.doPhase(b.getPublic(), true);
        try
        {
            kaBlank.generateSecret("   ");
            Assertions.fail("expected NoSuchAlgorithmException for blank algorithm name");
        }
        catch (NoSuchAlgorithmException expected)
        {
            Assertions.assertEquals("algorithm name must be non-null and non-blank",
                    expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // FIPS capability locks: paramgen substitution, q-less agreement
    // -----------------------------------------------------------------

    /**
     * The OpenSSL FIPS providers never run the PKCS#3 safe-prime search —
     * paramgen silently substitutes the RFC 7919 named group matching the
     * requested size (probe-confirmed on 3.1.2). The provider's contract is
     * fail-loud: callers asked for freshly generated parameters and must not
     * receive fixed constants undetected, so
     * {@code AlgorithmParameterGenerator.generateParameters()} throws
     * ProviderException with the pinned capability message (named-group key
     * generation via {@code KeyPairGenerator.initialize(int)} is the
     * supported route).
     */
    @Test
    public void dhAlgorithmParameterGeneratorRefusesNamedGroupSubstitution() throws Exception
    {
        ensureProviders();

        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DH", FIPS);
        apg.init(2048, RANDOM);
        try
        {
            apg.generateParameters();
            Assertions.fail("expected ProviderException — FIPS paramgen substitutes ffdhe2048");
        }
        catch (ProviderException expected)
        {
            Assertions.assertEquals(
                    "DH parameter generation is not supported by the loaded provider (a named group would be substituted); use named-group key generation instead",
                    expected.getMessage());
        }
    }

    /**
     * The FIPS module requires the subgroup order q at derive-init
     * (SP 800-56A key check), so a q-less PKCS#3 component private key —
     * built through the FIPS provider's own KeyFactory from a
     * {@code DHPrivateKeySpec} (p, g, x) — is rejected at
     * {@code KeyAgreement.init} with InvalidKeyException and the pinned
     * message. The prime MUST be a non-named safe prime: OpenSSL back-fills
     * q for recognised named-group (p, g) pairs on import, which would
     * disarm the check (see
     * {@link FIPSTestUtil#NON_NAMED_SAFE_PRIME_2048_HEX}). Named-group DH
     * agreement (ffdhe2048 keygen keys, which carry q) is unaffected — see
     * the agreement tests above and FIPSDHAgreementTest.
     */
    @Test
    public void dhQlessComponentPrivateKey_initThrowsInvalidKeyException() throws Exception
    {
        ensureProviders();

        BigInteger p = new BigInteger(FIPSTestUtil.NON_NAMED_SAFE_PRIME_2048_HEX, 16);
        BigInteger g = BigInteger.valueOf(2);
        // Random private value; the set top bit keeps it non-zero (and it is
        // far below p). 225 bits per the safe-prime recommended length.
        BigInteger x = new BigInteger(225, RANDOM).setBit(224);

        KeyFactory kf = KeyFactory.getInstance("DH", FIPS);
        PrivateKey priv = kf.generatePrivate(new DHPrivateKeySpec(x, p, g));

        KeyAgreement ka = KeyAgreement.getInstance("DH", FIPS);
        try
        {
            ka.init(priv);
            Assertions.fail("expected InvalidKeyException for a q-less PKCS#3 key under FIPS");
        }
        catch (InvalidKeyException expected)
        {
            Assertions.assertEquals(
                    "DH key without subgroup order q is not supported for key agreement by the loaded provider",
                    expected.getMessage());
        }
    }
}
