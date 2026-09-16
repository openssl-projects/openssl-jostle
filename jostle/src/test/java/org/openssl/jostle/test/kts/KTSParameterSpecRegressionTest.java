/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.kts;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * D50/C43 regressions for {@link KTSParameterSpec}: BouncyCastle's own spec
 * type is refused typed by both KTS ciphers, and this class's own Builder is
 * what they accept — round-tripping every KDF shape and refusing malformed
 * construction.
 */
public class KTSParameterSpecRegressionTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyPair rsaPair;
    private static KeyPair mlKemPair;

    @BeforeAll
    public static void setUp() throws Exception
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", JSL);
        rsaKpg.initialize(2048, RANDOM);
        rsaPair = rsaKpg.generateKeyPair();
        mlKemPair = KeyPairGenerator.getInstance("ML-KEM-768", JSL).generateKeyPair();
    }

    private static SecretKey cek() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(256, RANDOM);
        return kg.generateKey();
    }

    // -----------------------------------------------------------------
    // A BouncyCastle spec is refused, typed, naming the Jostle class.
    // -----------------------------------------------------------------

    @Test
    public void bcSpecRefusedByRsaKts() throws Exception
    {
        org.bouncycastle.jcajce.spec.KTSParameterSpec bcSpec =
                new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AESWRAP", 256).build();
        Cipher c = Cipher.getInstance("RSA-KTS-KEM-KWS", JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, rsaPair.getPublic(), bcSpec, RANDOM));
        Assertions.assertTrue(e.getMessage().contains("org.openssl.jostle.jcajce.spec.KTSParameterSpec"),
                "message must name the Jostle class: " + e.getMessage());
    }

    @Test
    public void bcSpecRefusedByMlKemKts() throws Exception
    {
        org.bouncycastle.jcajce.spec.KTSParameterSpec bcSpec =
                new org.bouncycastle.jcajce.spec.KTSParameterSpec.Builder("AES", 256).build();
        Cipher c = Cipher.getInstance("ML-KEM", JSL);
        InvalidAlgorithmParameterException e = Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, mlKemPair.getPublic(), bcSpec, RANDOM));
        Assertions.assertTrue(e.getMessage().contains("org.openssl.jostle.jcajce.spec.KTSParameterSpec"),
                "message must name the Jostle class: " + e.getMessage());
    }

    // -----------------------------------------------------------------
    // The Jostle spec itself round-trips, every KDF shape, both ciphers.
    // -----------------------------------------------------------------

    private static void roundTrip(String transformation, Key pub, Key priv, KTSParameterSpec spec)
        throws Exception
    {
        SecretKey cek = cek();
        Cipher w = Cipher.getInstance(transformation, JSL);
        w.init(Cipher.WRAP_MODE, pub, spec, RANDOM);
        byte[] wrapped = w.wrap(cek);

        Cipher u = Cipher.getInstance(transformation, JSL);
        u.init(Cipher.UNWRAP_MODE, priv, spec, RANDOM);
        Key recovered = u.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                transformation + ": did not round-trip");
    }

    @Test
    public void defaultKdfRoundTripsOnBothCiphers() throws Exception
    {
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        // Default KDF: neither withKdfAlgorithm nor withNoKdf called.
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo).build();
        roundTrip("RSA-KTS-KEM-KWS", rsaPair.getPublic(), rsaPair.getPrivate(), spec);

        KTSParameterSpec kemSpec = new KTSParameterSpec.Builder("AES", 256, otherInfo).build();
        roundTrip("ML-KEM", mlKemPair.getPublic(), mlKemPair.getPrivate(), kemSpec);
    }

    @Test
    public void explicitKdf3Sha512RoundTripsOnBothCiphers() throws Exception
    {
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo)
                .withKdfAlgorithm(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha512)
                .build();
        roundTrip("RSA-KTS-KEM-KWS", rsaPair.getPublic(), rsaPair.getPrivate(), spec);

        KTSParameterSpec kemSpec = new KTSParameterSpec.Builder("AES", 256, otherInfo)
                .withKdfAlgorithm(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha512)
                .build();
        roundTrip("ML-KEM", mlKemPair.getPublic(), mlKemPair.getPrivate(), kemSpec);
    }

    @Test
    public void hkdfSha256RoundTripsOnBothCiphers() throws Exception
    {
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        // HKDF OIDs name their digest in the OID itself — no digest argument.
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo)
                .withKdfAlgorithm(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, null)
                .build();
        roundTrip("RSA-KTS-KEM-KWS", rsaPair.getPublic(), rsaPair.getPrivate(), spec);

        KTSParameterSpec kemSpec = new KTSParameterSpec.Builder("AES", 256, otherInfo)
                .withKdfAlgorithm(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, null)
                .build();
        roundTrip("ML-KEM", mlKemPair.getPublic(), mlKemPair.getPrivate(), kemSpec);
    }

    @Test
    public void noKdfRoundTripsOnBothCiphers() throws Exception
    {
        byte[] otherInfo = new byte[16];
        RANDOM.nextBytes(otherInfo);
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo).withNoKdf().build();
        roundTrip("RSA-KTS-KEM-KWS", rsaPair.getPublic(), rsaPair.getPrivate(), spec);

        KTSParameterSpec kemSpec = new KTSParameterSpec.Builder("AES", 256, otherInfo).withNoKdf().build();
        roundTrip("ML-KEM", mlKemPair.getPublic(), mlKemPair.getPrivate(), kemSpec);
    }

    // -----------------------------------------------------------------
    // Builder refusals.
    // -----------------------------------------------------------------

    @Test
    public void nullAlgorithmNameRefused()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new KTSParameterSpec.Builder(null, 256));
    }

    @Test
    public void zeroKeySizeRefused()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new KTSParameterSpec.Builder("AESWRAP", 0));
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new KTSParameterSpec.Builder("AESWRAP", -1));
    }

    @Test
    public void oversizeKdfAlgorithmDerRefused()
    {
        byte[] tooLong = new byte[257];
        RANDOM.nextBytes(tooLong);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new KTSParameterSpec.Builder("AESWRAP", 256).withKdfAlgorithm(tooLong));
    }

    @Test
    public void nullKdfAlgorithmDerThrowsNpe()
    {
        Assertions.assertThrows(NullPointerException.class,
                () -> new KTSParameterSpec.Builder("AESWRAP", 256).withKdfAlgorithm((byte[]) null));
    }

    @Test
    public void nullKdfOidThrowsNpe()
    {
        Assertions.assertThrows(NullPointerException.class,
                () -> new KTSParameterSpec.Builder("AESWRAP", 256)
                        .withKdfAlgorithm(null, NISTObjectIdentifiers.id_sha256));
    }

    /**
     * Malformed KDF AlgorithmIdentifier DER is refused at init, on both
     * ciphers: truncated, trailing garbage, and an extra element after the
     * digest AlgorithmIdentifier inside the outer SEQUENCE (exercises
     * KtsKdf.resolve's requireEnd). Built with {@link Der} directly, so the
     * test does not depend on BC's encoder.
     */
    @Test
    public void malformedKdfDerRefusedAtInit() throws Exception
    {
        byte[] kdfOid = Der.objectIdentifier(X9ObjectIdentifiers.id_kdf_kdf3.getId());
        byte[] digestAlgId = Der.sequence(Der.objectIdentifier(NISTObjectIdentifiers.id_sha256.getId()));
        byte[] wellFormed = Der.sequence(kdfOid, digestAlgId);

        byte[] truncated = Arrays.copyOfRange(wellFormed, 0, wellFormed.length - 2);
        byte[] trailingByte = Arrays.concatenate(wellFormed, new byte[]{0x00});
        byte[] extraElementAfterDigest = Der.sequence(kdfOid, digestAlgId,
                Der.objectIdentifier(NISTObjectIdentifiers.id_sha256.getId()));

        for (byte[] malformed : new byte[][]{truncated, trailingByte, extraElementAfterDigest})
        {
            assertRefusedAtInit("RSA-KTS-KEM-KWS", rsaPair.getPublic(), malformed);
            assertRefusedAtInit("ML-KEM", mlKemPair.getPublic(), malformed);
        }
    }

    private static void assertRefusedAtInit(String transformation, java.security.PublicKey pub,
                                             byte[] malformedKdfDer) throws Exception
    {
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", 256).withKdfAlgorithm(malformedKdfDer).build();
        Cipher c = Cipher.getInstance(transformation, JSL);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, pub, spec, RANDOM),
                transformation + ": malformed KDF DER must be refused at init");
    }

    // -----------------------------------------------------------------
    // Getters return copies.
    // -----------------------------------------------------------------

    @Test
    public void gettersReturnCopies()
    {
        byte[] otherInfo = {1, 2, 3, 4};
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AESWRAP", 256, otherInfo)
                .withKdfAlgorithm(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha256)
                .build();

        byte[] gotOtherInfo = spec.getOtherInfo();
        gotOtherInfo[0] ^= (byte) 0xFF;
        Assertions.assertFalse(Arrays.areEqual(gotOtherInfo, spec.getOtherInfo()),
                "mutating the returned otherInfo must not affect the spec");

        byte[] gotKdf = spec.getKdfAlgorithm();
        gotKdf[0] ^= (byte) 0xFF;
        Assertions.assertFalse(Arrays.areEqual(gotKdf, spec.getKdfAlgorithm()),
                "mutating the returned kdfAlgorithm must not affect the spec");
    }
}
