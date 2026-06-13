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

package org.openssl.jostle.test.kdf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kdf.KeyAgreementKDF;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Byte-exact validation of {@link KeyAgreementKDF} against the BouncyCastle
 * primitives CMS key agreement is built on: the X9.42 KDF must match
 * {@code DHKEKGenerator} (including the {@code OtherInfo} DER our code builds
 * by hand) and the X9.63 KDF must match {@code KDF2BytesGenerator}. Random
 * shared secrets, UKMs, wrap algorithms, and output lengths across many trials.
 */
public class KeyAgreementKDFTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45"; // 32 bytes
    private static final String DESEDE_WRAP = "1.2.840.113549.1.9.16.3.6"; // 24 bytes
    private static final String ESDH_OID = "1.2.840.113549.1.9.16.3.5"; // id-alg-ESDH (DHwithRFC2631KDF)

    // Wrap OIDs and their KEK byte lengths.
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5",   // aes128-wrap -> 16
            "2.16.840.1.101.3.4.1.25",  // aes192-wrap -> 24
            AES256_WRAP,                // aes256-wrap -> 32
            DESEDE_WRAP                 // 3des-wrap   -> 24
    };

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

    private static KeyPair ecKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("P-256"));
        return kpg.generateKeyPair();
    }

    /** A finite-field DH keypair in the ffdhe2048 group (instant named-group keygen). */
    private static KeyPair dhKeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JostleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /** Raw ECDH shared secret (ZZ) via the plain "ECDH" transformation. */
    private static byte[] rawEcdh(KeyPair local, KeyPair peer) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", JostleProvider.PROVIDER_NAME);
        ka.init(local.getPrivate());
        ka.doPhase(peer.getPublic(), true);
        return ka.generateSecret();
    }

    private static Digest bcDigest(String name)
    {
        switch (name)
        {
        case "SHA-1":
            return new SHA1Digest();
        case "SHA-224":
            return new SHA224Digest();
        case "SHA-256":
            return new SHA256Digest();
        case "SHA-384":
            return new SHA384Digest();
        case "SHA-512":
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException(name);
        }
    }

    @Test
    public void x942_matchesBcDHKEKGenerator() throws Exception
    {
        for (int trial = 0; trial < 50; trial++)
        {
            byte[] zz = new byte[16 + RANDOM.nextInt(112)];
            RANDOM.nextBytes(zz);

            byte[] ukm = null;
            if (trial % 3 != 0)
            {
                ukm = new byte[1 + RANDOM.nextInt(40)];
                RANDOM.nextBytes(ukm);
            }

            String wrapOid = WRAP_OIDS[RANDOM.nextInt(WRAP_OIDS.length)];
            int keyLen = KeyAgreementKDF.wrapKeyLenBytes(wrapOid);

            byte[] jsl = KeyAgreementKDF.x942("SHA-1", zz, wrapOid, keyLen, ukm);

            DHKEKGenerator gen = new DHKEKGenerator(new SHA1Digest());
            gen.init(new DHKDFParameters(new ASN1ObjectIdentifier(wrapOid), keyLen * 8, zz, ukm));
            byte[] bc = new byte[keyLen];
            gen.generateBytes(bc, 0, keyLen);

            Assertions.assertArrayEquals(bc, jsl,
                    "X9.42 KDF diverged from DHKEKGenerator (wrap=" + wrapOid
                            + ", ukm=" + (ukm == null ? "none" : ukm.length) + ")");
        }
    }

    @Test
    public void x963_matchesBcKDF2Generator() throws Exception
    {
        String[] digests = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"};
        for (int trial = 0; trial < 60; trial++)
        {
            byte[] zz = new byte[24 + RANDOM.nextInt(80)];
            RANDOM.nextBytes(zz);

            byte[] sharedInfo = null;
            if (trial % 4 != 0)
            {
                sharedInfo = new byte[1 + RANDOM.nextInt(60)];
                RANDOM.nextBytes(sharedInfo);
            }

            String digest = digests[trial % digests.length];
            int keyLen = new int[]{16, 24, 32}[RANDOM.nextInt(3)];

            byte[] jsl = KeyAgreementKDF.x963(digest, zz, keyLen, sharedInfo);

            KDF2BytesGenerator gen = new KDF2BytesGenerator(bcDigest(digest));
            gen.init(new KDFParameters(zz, sharedInfo));
            byte[] bc = new byte[keyLen];
            gen.generateBytes(bc, 0, keyLen);

            Assertions.assertArrayEquals(bc, jsl,
                    "X9.63 KDF diverged from KDF2BytesGenerator (digest=" + digest
                            + ", keyLen=" + keyLen + ")");
        }
    }

    @Test
    public void x942_distinctUkmGivesDistinctKek() throws Exception
    {
        byte[] zz = new byte[48];
        RANDOM.nextBytes(zz);
        byte[] ukm1 = new byte[16];
        byte[] ukm2 = new byte[16];
        RANDOM.nextBytes(ukm1);
        RANDOM.nextBytes(ukm2);

        byte[] k1 = KeyAgreementKDF.x942("SHA-1", zz, WRAP_OIDS[2], 32, ukm1);
        byte[] k2 = KeyAgreementKDF.x942("SHA-1", zz, WRAP_OIDS[2], 32, ukm2);
        Assertions.assertFalse(Arrays.areEqual(k1, k2),
                "different UKMs must yield different KEKs");
    }

    @Test
    public void x963_distinctSharedInfoGivesDistinctKek() throws Exception
    {
        byte[] zz = new byte[48];
        RANDOM.nextBytes(zz);
        byte[] si1 = new byte[20];
        byte[] si2 = new byte[20];
        RANDOM.nextBytes(si1);
        RANDOM.nextBytes(si2);

        byte[] k1 = KeyAgreementKDF.x963("SHA-256", zz, 32, si1);
        byte[] k2 = KeyAgreementKDF.x963("SHA-256", zz, 32, si2);
        Assertions.assertFalse(Arrays.areEqual(k1, k2),
                "different SharedInfo must yield different KEKs");
    }

    // -----------------------------------------------------------------
    // JCE-surface tests of the *registered* ECDHwithSHAnnnKDF SPIs, cross-
    // validated against BouncyCastle's own provider (which registers the
    // identical transformations). Proves the provider wiring picks the
    // right digest per name (the ProvCAMELLIA/ProvARIA mis-registration
    // class) and that the KDF, UserKeyingMaterialSpec, 3DES-parity and
    // wrap-key-length behaviour match an independent implementation. The
    // four SHA-2 variants are exercised directly here; the CMS suite covers
    // SHA-1/SHA-256 through the CMS layer.
    // -----------------------------------------------------------------

    /** Registered JCE name, KDF digest, and the X9.63 scheme OID alias. */
    private static final String[][] KDF_NAME_DIGEST = {
            {"ECDHWITHSHA224KDF", "SHA-224", "1.3.132.1.11.0"},
            {"ECDHWITHSHA256KDF", "SHA-256", "1.3.132.1.11.1"},
            {"ECDHWITHSHA384KDF", "SHA-384", "1.3.132.1.11.2"},
            {"ECDHWITHSHA512KDF", "SHA-512", "1.3.132.1.11.3"},
    };

    /**
     * For every registered ECDHwithSHAnnnKDF transformation — looked up on the
     * Jostle side both by name AND by OID alias — the derived KEK must be
     * byte-identical to BouncyCastle's own provider deriving with the same EC
     * keys (exchanged via encoding) and the same UKM, across all wrap
     * algorithms (AES-128/192/256-wrap and 3DES-wrap, the last exercising the
     * RFC 3217 odd-parity step) and both the no-UKM and random-UKM cases.
     */
    @Test
    public void registeredEcdhKdf_agreesWithBouncyCastle() throws Exception
    {
        KeyFactory bcEcKf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);

        for (String[] nd : KDF_NAME_DIGEST)
        {
            final String name = nd[0];
            final String oid = nd[2];
            for (int trial = 0; trial < 3; trial++)
            {
                KeyPair alice = ecKeyPair();
                KeyPair bob = ecKeyPair();
                // Same keys on the BC side, imported through the standard encodings.
                PrivateKey bcAlicePriv = (PrivateKey) bcEcKf.generatePrivate(
                        new PKCS8EncodedKeySpec(alice.getPrivate().getEncoded()));
                PublicKey bcBobPub = (PublicKey) bcEcKf.generatePublic(
                        new X509EncodedKeySpec(bob.getPublic().getEncoded()));

                byte[] ukm = null;
                if (trial != 0)
                {
                    ukm = new byte[8 + RANDOM.nextInt(40)];
                    RANDOM.nextBytes(ukm);
                }

                for (String wrapOid : WRAP_OIDS)
                {
                    byte[] bc = bcDerive(name, bcAlicePriv, bcBobPub, ukm, wrapOid);
                    byte[] jslByName = jslDerive(name, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);
                    byte[] jslByOid = jslDerive(oid, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);

                    String ctx = name + " wrap=" + wrapOid
                            + " ukm=" + (ukm == null ? "none" : Integer.toString(ukm.length));
                    Assertions.assertArrayEquals(bc, jslByName,
                            ctx + ": JSL (by name) diverged from BouncyCastle");
                    Assertions.assertArrayEquals(bc, jslByOid,
                            ctx + ": JSL (by OID " + oid + ") diverged from BouncyCastle");
                }
            }
        }
    }

    /** Derive a wrapped KEK via the Jostle provider's ECDHwithKDF transformation. */
    private static byte[] jslDerive(String transform, PrivateKey priv, PublicKey peer,
                                    byte[] ukm, String wrapOid) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(transform, JostleProvider.PROVIDER_NAME);
        if (ukm == null)
        {
            ka.init(priv);
        }
        else
        {
            ka.init(priv, new UserKeyingMaterialSpec(ukm));
        }
        ka.doPhase(peer, true);
        return ka.generateSecret(wrapOid).getEncoded();
    }

    /** Derive the same via BouncyCastle's provider (independent reference). */
    private static byte[] bcDerive(String transform, PrivateKey priv, PublicKey peer,
                                   byte[] ukm, String wrapOid) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(transform, BouncyCastleProvider.PROVIDER_NAME);
        if (ukm == null)
        {
            ka.init(priv);
        }
        else
        {
            ka.init(priv, new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        ka.doPhase(peer, true);
        return ka.generateSecret(wrapOid).getEncoded();
    }

    /**
     * The registered finite-field DHwithRFC2631KDF transformation (the
     * id-alg-ESDH KeyAgreement, looked up on the Jostle side by name AND by
     * the ESDH OID alias) must derive a KEK byte-identical to BouncyCastle's
     * own provider — same ffdhe2048 DH keys (exchanged via encoding), same
     * UKM, across every wrap algorithm including 3DES, for the no-UKM and
     * random-UKM cases. Mirrors the EC agreement; closes the same
     * helper-only-validation gap on the X9.42 DH side.
     */
    @Test
    public void registeredDhKdf_agreesWithBouncyCastle() throws Exception
    {
        KeyFactory bcDhKf = KeyFactory.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair alice = dhKeyPair();
        KeyPair bob = dhKeyPair();
        PrivateKey bcAlicePriv = (PrivateKey) bcDhKf.generatePrivate(
                new PKCS8EncodedKeySpec(alice.getPrivate().getEncoded()));
        PublicKey bcBobPub = (PublicKey) bcDhKf.generatePublic(
                new X509EncodedKeySpec(bob.getPublic().getEncoded()));

        for (int trial = 0; trial < 2; trial++)
        {
            byte[] ukm = null;
            if (trial != 0)
            {
                ukm = new byte[8 + RANDOM.nextInt(40)];
                RANDOM.nextBytes(ukm);
            }

            for (String wrapOid : WRAP_OIDS)
            {
                byte[] bc = bcDerive(ESDH_OID, bcAlicePriv, bcBobPub, ukm, wrapOid);
                byte[] jslByName = jslDerive("DHWITHRFC2631KDF", alice.getPrivate(), bob.getPublic(), ukm, wrapOid);
                byte[] jslByOid = jslDerive(ESDH_OID, alice.getPrivate(), bob.getPublic(), ukm, wrapOid);

                String ctx = "DHwithRFC2631KDF wrap=" + wrapOid
                        + " ukm=" + (ukm == null ? "none" : Integer.toString(ukm.length));
                Assertions.assertArrayEquals(bc, jslByName,
                        ctx + ": JSL (by name) diverged from BouncyCastle");
                Assertions.assertArrayEquals(bc, jslByOid,
                        ctx + ": JSL (by ESDH OID) diverged from BouncyCastle");
            }
        }
    }

    /**
     * The Jostle {@link UserKeyingMaterialSpec} must be honoured: distinct UKM
     * → distinct KEK, identical UKM → identical KEK (deterministic), and a
     * non-UKM spec is rejected with {@link InvalidAlgorithmParameterException}.
     */
    @Test
    public void registeredEcdhKdf_userKeyingMaterialSpecHonoured() throws Exception
    {
        KeyPair alice = ecKeyPair();
        KeyPair bob = ecKeyPair();

        byte[] ukm1 = new byte[20];
        byte[] ukm2 = new byte[20];
        RANDOM.nextBytes(ukm1);
        RANDOM.nextBytes(ukm2);

        byte[] k1 = deriveWithUkm(alice, bob, ukm1);
        byte[] k1again = deriveWithUkm(alice, bob, ukm1);
        byte[] k2 = deriveWithUkm(alice, bob, ukm2);

        Assertions.assertArrayEquals(k1, k1again, "same UKM must derive the same KEK");
        Assertions.assertFalse(Arrays.areEqual(k1, k2), "distinct UKM must derive distinct KEKs");

        KeyAgreement ka = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> ka.init(alice.getPrivate(), new IvParameterSpec(new byte[16])),
                "a non-UKM AlgorithmParameterSpec must be rejected");
    }

    private static byte[] deriveWithUkm(KeyPair local, KeyPair peer, byte[] ukm) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JostleProvider.PROVIDER_NAME);
        ka.init(local.getPrivate(), new UserKeyingMaterialSpec(ukm));
        ka.doPhase(peer.getPublic(), true);
        return ka.generateSecret(AES256_WRAP).getEncoded();
    }

    /**
     * BC parity (the fix that sealed the raw forms): the pre-KDF shared secret
     * must never escape a KDF agreement — both {@code generateSecret()} and
     * {@code generateSecret(byte[], int)} throw.
     */
    @Test
    public void registeredEcdhKdf_rawSecretFormsAreSealed() throws Exception
    {
        KeyPair alice = ecKeyPair();
        KeyPair bob = ecKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);

        Assertions.assertThrows(UnsupportedOperationException.class, ka::generateSecret,
                "raw generateSecret() must be sealed on a KDF agreement");
        Assertions.assertThrows(UnsupportedOperationException.class,
                () -> ka.generateSecret(new byte[64], 0),
                "raw generateSecret(byte[],int) must be sealed on a KDF agreement");
    }

    /**
     * Regression guard: the 3DES KEK is the RAW X9.63 KDF output, NOT
     * odd-parity-adjusted. BouncyCastle's KeyAgreement surface returns the raw
     * bytes (DES wrapping ignores parity), so byte-exact agreement requires
     * Jostle to do the same — a re-introduced {@code setOddParity} would flip
     * the parity bits and diverge. (The cross-provider agreement test above
     * exercises 3DES against BC directly; this pins the no-parity invariant
     * against the BC-validated {@link KeyAgreementKDF#x963} helper.)
     */
    @Test
    public void registeredEcdhKdf_desEdeKekIsRawNoParity() throws Exception
    {
        KeyPair alice = ecKeyPair();
        KeyPair bob = ecKeyPair();
        byte[] zz = rawEcdh(alice, bob);

        byte[] ukm = new byte[16];
        RANDOM.nextBytes(ukm);
        int keyLen = KeyAgreementKDF.wrapKeyLenBytes(DESEDE_WRAP);
        byte[] rawKdf = KeyAgreementKDF.x963("SHA-256", zz, keyLen, ukm);

        KeyAgreement ka = KeyAgreement.getInstance("ECDHWITHSHA256KDF", JostleProvider.PROVIDER_NAME);
        ka.init(alice.getPrivate(), new UserKeyingMaterialSpec(ukm));
        ka.doPhase(bob.getPublic(), true);
        byte[] kek = ka.generateSecret(DESEDE_WRAP).getEncoded();

        Assertions.assertEquals(24, kek.length, "3DES KEK must be 24 bytes");
        Assertions.assertArrayEquals(rawKdf, kek,
                "3DES KEK must be the raw KDF output (no odd-parity adjustment), matching BouncyCastle");
    }
}
