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

package org.openssl.jostle.test.mlkem;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests for {@code MLKEMKTSCipherSpi} — the ML-KEM KTS (key-transport) Cipher
 * used on the CMS KEMRecipientInfo path (RFC 9629).
 * <p>
 * The wire format produced by wrap is {@code encapsulation ‖ AES-KW(KDF3(secret), cek)};
 * unwrap is the inverse. The {@code AlgorithmParameterSpec} is BouncyCastle's
 * {@code KTSParameterSpec} (read reflectively by the SPI), so these tests build it
 * with the same configuration the SPI hardcodes — plain AES key-wrap (RFC 3394,
 * the {@code "AES"} wrapper name) and X9.44 KDF3 — which is exactly the
 * configuration BC's own {@code MLKEMCipherSpi} resolves to via {@code WrapUtil}.
 * That alignment is what makes the cross-provider agreement tests meaningful.
 */
public class MLKEMKTSCipherTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The three ML-KEM KeyPairGenerator names Jostle exposes, paired with the
     * SPKI/KEM OID each registers the KTS Cipher under (the .4.4 "kems" arc).
     */
    private static final String[] KPG_NAMES = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    private static final String[] KEM_OIDS = {
            "2.16.840.1.101.3.4.4.1",
            "2.16.840.1.101.3.4.4.2",
            "2.16.840.1.101.3.4.4.3"
    };

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    public static void before()
    {
        synchronized (JostleProvider.class)
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
    }

    /**
     * The X9.44 KDF3 AlgorithmIdentifier {@code SEQUENCE { kdf3-OID, SEQUENCE { digestOID } }}
     * BC's KTSParameterSpec carries and the SPI parses reflectively.
     */
    private static AlgorithmIdentifier kdf3(ASN1ObjectIdentifier digestOid)
    {
        return new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(digestOid));
    }

    private static KTSParameterSpec ktsKdf3Spec(int keyBits, byte[] otherInfo, ASN1ObjectIdentifier digestOid)
    {
        return new KTSParameterSpec.Builder("AES", keyBits, otherInfo)
                .withKdfAlgorithm(kdf3(digestOid))
                .build();
    }

    private static SecretKeySpec randomAesKey(SecureRandom rng, int lenBytes)
    {
        byte[] k = new byte[lenBytes];
        rng.nextBytes(k);
        return new SecretKeySpec(k, "AES");
    }

    private static byte[] randomBytes(SecureRandom rng, int len)
    {
        byte[] b = new byte[len];
        rng.nextBytes(b);
        return b;
    }

    private static KeyPair jostleKeyPair(String name) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, JostleProvider.PROVIDER_NAME);
        return kpg.generateKeyPair();
    }

    // ----------------------------------------------------------------------
    // Positive round-trip across every parameter set, KDF3 + every legal CEK size
    // ----------------------------------------------------------------------

    @Test
    public void testWrapUnwrapRoundTrip_kdf3_allParamSetsAndKeySizes() throws Exception
    {
        SecureRandom rng = seededRandom("testWrapUnwrapRoundTrip_kdf3_allParamSetsAndKeySizes");

        for (String name : KPG_NAMES)
        {
            KeyPair kp = jostleKeyPair(name);

            // The KEK size selects the AES-KW key-schedule branch (AES-128/192/256)
            // inside aesKeyWrap(); cover all three. RFC 3394 AES-KW accepts CEKs that
            // are a multiple of 8 bytes, and the common AES key sizes 16/24/32 cover
            // the realistic CEK lengths.
            for (int kekBits : new int[]{128, 192, 256})
            {
                for (int cekLen : new int[]{16, 24, 32})
                {
                    byte[] otherInfo = randomBytes(rng, 1 + rng.nextInt(40));
                    KTSParameterSpec spec = ktsKdf3Spec(kekBits, otherInfo, NISTObjectIdentifiers.id_sha256);
                    SecretKeySpec cek = randomAesKey(rng, cekLen);

                    Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
                    wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
                    byte[] wrapped = wrap.wrap(cek);

                    Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
                    unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
                    Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

                    Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                            name + "/kek=" + kekBits + "/cek=" + cekLen + ": unwrapped CEK did not match");
                    Assertions.assertEquals("AES", recovered.getAlgorithm());
                }
            }
        }
    }

    @Test
    public void testWrapUnwrapRoundTrip_noKdf() throws Exception
    {
        SecureRandom rng = seededRandom("testWrapUnwrapRoundTrip_noKdf");
        KeyPair kp = jostleKeyPair("ML-KEM-768");

        // withNoKdf(): the 32-byte ML-KEM shared secret is used directly as the
        // KEK, so the KEK size must not exceed 256 bits.
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256, randomBytes(rng, 16))
                .withNoKdf()
                .build();
        SecretKeySpec cek = randomAesKey(rng, 16);

        Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
        byte[] wrapped = wrap.wrap(cek);

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded());
    }

    @Test
    public void testJostleCipherResolvableByOid() throws Exception
    {
        // CMS resolves the KTS cipher by OID, not by name — exercise the OID
        // alias registration in ProvMLKEM for every parameter set.
        SecureRandom rng = seededRandom("testJostleCipherResolvableByOid");
        for (int i = 0; i < KPG_NAMES.length; i++)
        {
            KeyPair kp = jostleKeyPair(KPG_NAMES[i]);
            KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);
            SecretKeySpec cek = randomAesKey(rng, 16);

            Cipher wrap = Cipher.getInstance(KEM_OIDS[i], JostleProvider.PROVIDER_NAME);
            wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
            byte[] wrapped = wrap.wrap(cek);

            Cipher unwrap = Cipher.getInstance(KEM_OIDS[i], JostleProvider.PROVIDER_NAME);
            unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
            Key recovered = unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(), KEM_OIDS[i]);
        }
    }

    // ----------------------------------------------------------------------
    // Negative paths
    // ----------------------------------------------------------------------

    @Test
    public void testTamperedEncapsulation_rejected() throws Exception
    {
        SecureRandom rng = seededRandom("testTamperedEncapsulation_rejected");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);

        Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
        byte[] wrapped = wrap.wrap(randomAesKey(rng, 16));

        // Flip a byte inside the ML-KEM encapsulation (the leading region). ML-KEM
        // decap implicit-rejects to a *different* shared secret, so the derived KEK
        // changes and the AES-KW integrity check fails -> InvalidKeyException.
        wrapped[0] ^= 0x01;

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        byte[] frozen = wrapped;
        // Must be InvalidKeyException — the unwrap boundary must not surface a
        // BadPaddingException (Bleichenbacher channel; see java-spi.md). The type
        // assertion below is the guard: BadPaddingException is not an
        // InvalidKeyException, so a leak of it would fail assertThrows here.
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap.unwrap(frozen, "AES", Cipher.SECRET_KEY));
    }

    @Test
    public void testTamperedWrappedKey_rejected() throws Exception
    {
        SecureRandom rng = seededRandom("testTamperedWrappedKey_rejected");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);

        Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
        byte[] wrapped = wrap.wrap(randomAesKey(rng, 16));

        // The last byte is in the AES-KW region (well past the 1088-byte ML-KEM-768
        // encapsulation); corrupting it must fail the key-wrap integrity check.
        wrapped[wrapped.length - 1] ^= 0x01;

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        byte[] frozen = wrapped;
        Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap.unwrap(frozen, "AES", Cipher.SECRET_KEY));
    }

    @Test
    public void testTruncatedInput_rejected() throws Exception
    {
        SecureRandom rng = seededRandom("testTruncatedInput_rejected");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);

        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                () -> unwrap.unwrap(new byte[10], "AES", Cipher.SECRET_KEY));
        Assertions.assertEquals("input shorter than ML-KEM encapsulation", ex.getMessage());
    }

    @Test
    public void testUnsupportedKdf_rejected() throws Exception
    {
        SecureRandom rng = seededRandom("testUnsupportedKdf_rejected");
        KeyPair kp = jostleKeyPair("ML-KEM-768");

        // KDF2 instead of KDF3 — the SPI only supports X9.44 KDF3.
        AlgorithmIdentifier kdf2 = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_kdf_kdf2, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256, randomBytes(rng, 8))
                .withKdfAlgorithm(kdf2)
                .build();

        Cipher c = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), spec));
        Assertions.assertTrue(ex.getMessage().contains("KDF3"),
                "message should name the only supported KDF: " + ex.getMessage());
    }

    @Test
    public void testInitWithoutSpec_rejected() throws Exception
    {
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        Cipher c = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        // The 3-arg init path (no AlgorithmParameterSpec) cannot supply the KTS spec.
        Assertions.assertThrows(InvalidKeyException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic()));
    }

    @Test
    public void testInitWrongSpecType_rejected() throws Exception
    {
        SecureRandom rng = seededRandom("testInitWrongSpecType_rejected");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        Cipher c = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPublic(), new IvParameterSpec(randomBytes(rng, 12))));
    }

    @Test
    public void testWrapModeRequiresPublicKey() throws Exception
    {
        SecureRandom rng = seededRandom("testWrapModeRequiresPublicKey");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);
        Cipher c = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> c.init(Cipher.WRAP_MODE, kp.getPrivate(), spec));
    }

    @Test
    public void testUnwrapModeRequiresPrivateKey() throws Exception
    {
        SecureRandom rng = seededRandom("testUnwrapModeRequiresPrivateKey");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);
        Cipher c = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidKeyException.class,
                () -> c.init(Cipher.UNWRAP_MODE, kp.getPublic(), spec));
    }

    // ----------------------------------------------------------------------
    // Reset / reuse
    // ----------------------------------------------------------------------

    @Test
    public void testReuse_randomisedOutput_andRoundTrip() throws Exception
    {
        SecureRandom rng = seededRandom("testReuse_randomisedOutput_andRoundTrip");
        KeyPair kp = jostleKeyPair("ML-KEM-768");
        KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 8), NISTObjectIdentifiers.id_sha256);
        SecretKeySpec cek = randomAesKey(rng, 16);

        Cipher wrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        wrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);

        // Two wraps of the SAME CEK on the SAME instance must differ — ML-KEM
        // encapsulation is randomised per call, so a frozen/cached encapsulation
        // would be a real correctness bug.
        byte[] w1 = wrap.wrap(cek);
        byte[] w2 = wrap.wrap(cek);
        Assertions.assertFalse(Arrays.areEqual(w1, w2), "reused wrap cipher produced identical output");

        Cipher unwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
        unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
        Assertions.assertArrayEquals(cek.getEncoded(), unwrap.unwrap(w1, "AES", Cipher.SECRET_KEY).getEncoded());
        Assertions.assertArrayEquals(cek.getEncoded(), unwrap.unwrap(w2, "AES", Cipher.SECRET_KEY).getEncoded());
    }

    // ----------------------------------------------------------------------
    // Cross-provider agreement against BouncyCastle (the real interop guarantee)
    // ----------------------------------------------------------------------

    @Test
    public void testCrossProvider_JostleWrap_BCUnwrap() throws Exception
    {
        SecureRandom rng = seededRandom("testCrossProvider_JostleWrap_BCUnwrap");

        for (int t = 0; t < 5; t++)
        {
            KeyPair kp = jostleKeyPair("ML-KEM-768");
            PrivateKey bcPriv = bcImportPrivate(kp);
            KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 1 + rng.nextInt(32)), NISTObjectIdentifiers.id_sha256);
            SecretKeySpec cek = randomAesKey(rng, 16 + 8 * rng.nextInt(3));

            Cipher jslWrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            jslWrap.init(Cipher.WRAP_MODE, kp.getPublic(), spec);
            byte[] wrapped = jslWrap.wrap(cek);

            Cipher bcUnwrap = Cipher.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            bcUnwrap.init(Cipher.UNWRAP_MODE, bcPriv, spec);
            Key recovered = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                    "trial " + t + ": BC could not recover Jostle-wrapped CEK");
        }
    }

    @Test
    public void testCrossProvider_BCWrap_JostleUnwrap() throws Exception
    {
        SecureRandom rng = seededRandom("testCrossProvider_BCWrap_JostleUnwrap");

        for (int t = 0; t < 5; t++)
        {
            KeyPair kp = jostleKeyPair("ML-KEM-768");
            PublicKey bcPub = bcImportPublic(kp);
            KTSParameterSpec spec = ktsKdf3Spec(256, randomBytes(rng, 1 + rng.nextInt(32)), NISTObjectIdentifiers.id_sha256);
            SecretKeySpec cek = randomAesKey(rng, 16 + 8 * rng.nextInt(3));

            Cipher bcWrap = Cipher.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            bcWrap.init(Cipher.WRAP_MODE, bcPub, spec);
            byte[] wrapped = bcWrap.wrap(cek);

            Cipher jslUnwrap = Cipher.getInstance("ML-KEM", JostleProvider.PROVIDER_NAME);
            jslUnwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate(), spec);
            Key recovered = jslUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            Assertions.assertArrayEquals(cek.getEncoded(), recovered.getEncoded(),
                    "trial " + t + ": Jostle could not recover BC-wrapped CEK");
        }
    }

    private static PublicKey bcImportPublic(KeyPair jostleKeyPair) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new X509EncodedKeySpec(jostleKeyPair.getPublic().getEncoded()));
    }

    private static PrivateKey bcImportPrivate(KeyPair jostleKeyPair) throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(jostleKeyPair.getPrivate().getEncoded()));
    }
}
