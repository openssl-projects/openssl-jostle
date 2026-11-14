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

package org.openssl.jostle.test.ec;

import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.test.dh.KeyAgreementCalls;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Cofactor ECDH (SEC 1 3.3.2) under the names and RFC 5753 OIDs CMS uses, against BouncyCastle 1.87. The secret is
 * derived from h*d*Q, so it equals plain ECDH on a curve whose cofactor is 1 and differs from it where the cofactor
 * is above 1; the cofactor curves are what prove the mode is applied rather than aliased.
 */
public class ECCofactorAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** Cofactor 1. */
    private static final String[] PRIME_CURVES = {"P-256", "P-384", "P-521"};

    /** Cofactor 4 and 2. */
    private static final String[] COFACTOR_CURVES = {"sect233k1", "sect163k1"};

    /** The raw names: BouncyCastle registers both for one SPI. */
    private static final String[] RAW_NAMES = {"ECCDH", "ECDHC"};

    /** Name, then its RFC 5753 dhSinglePass-cofactorDH OID. */
    private static final String[][] KDF_NAMES = {
        {"ECCDHWITHSHA1KDF", "1.3.133.16.840.63.0.3"},
        {"ECCDHWITHSHA224KDF", "1.3.132.1.14.0"},
        {"ECCDHWITHSHA256KDF", "1.3.132.1.14.1"},
        {"ECCDHWITHSHA384KDF", "1.3.132.1.14.2"},
        {"ECCDHWITHSHA512KDF", "1.3.132.1.14.3"}};

    /** AES key-wrap OIDs: 16, 24 and 32-byte KEKs. */
    private static final String[] WRAP_OIDS = {
        "2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.45"};

    private static final int TRIALS = 3;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static KeyPair generate(String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static PublicKey toBc(PublicKey key) throws Exception
    {
        return KeyFactory.getInstance("EC", BC).generatePublic(new X509EncodedKeySpec(key.getEncoded()));
    }

    private static PrivateKey toBc(PrivateKey key) throws Exception
    {
        return KeyFactory.getInstance("EC", BC).generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
    }

    private static byte[] raw(String provider, String name, PrivateKey priv, PublicKey peer) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(name, provider);
        ka.init(priv);
        KeyAgreementCalls.phase(ka, peer);
        return KeyAgreementCalls.secret(ka);
    }

    private static byte[] kdf(String provider, String name, PrivateKey priv, PublicKey peer, byte[] ukm, String wrap)
            throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(name, provider);
        if (BC.equals(provider))
        {
            // UserKeyingMaterialSpec: BouncyCastle's is qualified, jostle's is imported
            ka.init(priv, new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm));
        }
        else
        {
            ka.init(priv, new UserKeyingMaterialSpec(ukm));
        }
        KeyAgreementCalls.phase(ka, peer);
        return KeyAgreementCalls.secret(ka, wrap).getEncoded();
    }

    private static List<String> curves()
    {
        List<String> all = new ArrayList<String>();
        Collections.addAll(all, PRIME_CURVES);
        Collections.addAll(all, COFACTOR_CURVES);
        return all;
    }

    /** Both raw names agree with BouncyCastle on every curve, each side computing from its own half. */
    @Test
    public void rawCofactorSecretAgreesWithBouncyCastle() throws Exception
    {
        int checked = 0;
        for (String curve : curves())
        {
            for (String name : RAW_NAMES)
            {
                for (int t = 0; t < TRIALS; t++)
                {
                    KeyPair a = generate(curve);
                    KeyPair b = generate(curve);
                    byte[] ours = raw(JSL, name, a.getPrivate(), b.getPublic());
                    byte[] ref = raw(BC, name, toBc(b.getPrivate()), toBc(a.getPublic()));
                    Assertions.assertArrayEquals(ref, ours, curve + " " + name);
                    byte[] other = raw(JSL, name, a.getPrivate(), generate(curve).getPublic());
                    Assertions.assertFalse(Arrays.areEqual(ours, other), curve + " " + name + ": a new peer");
                    checked++;
                }
            }
        }
        Assertions.assertEquals(5 * 2 * TRIALS, checked, "every curve and name must be driven");
    }

    /**
     * The property that separates the mode from an alias: where the cofactor is above 1 the secret differs from
     * plain ECDH, each matching BouncyCastle's own; where it is 1 the two are equal.
     */
    @Test
    public void cofactorSecretDiffersFromPlainEcdhOnlyWhereTheCofactorIsAboveOne() throws Exception
    {
        for (String curve : curves())
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            byte[] cofactor = raw(JSL, "ECCDH", a.getPrivate(), b.getPublic());
            byte[] plain = raw(JSL, "ECDH", a.getPrivate(), b.getPublic());
            Assertions.assertArrayEquals(raw(BC, "ECDH", toBc(a.getPrivate()), toBc(b.getPublic())), plain, curve);
            boolean prime = !curve.startsWith("sect");
            Assertions.assertEquals(prime, Arrays.areEqual(cofactor, plain),
                    curve + (prime ? ": cofactor 1 must equal plain ECDH" : ": cofactor above 1 must differ"));
        }
    }

    /** Every KDF name and its OID agree with BouncyCastle for every KEK length; the UKM changes the KEK. */
    @Test
    public void everyCofactorKdfNameAndOidAgreesWithBouncyCastle() throws Exception
    {
        int checked = 0;
        for (String curve : new String[]{"P-256", "sect233k1"})
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            for (String[] entry : KDF_NAMES)
            {
                for (String name : entry)
                {
                    for (String wrap : WRAP_OIDS)
                    {
                        byte[] ukm = new byte[1 + RANDOM.nextInt(64)];
                        RANDOM.nextBytes(ukm);
                        String label = curve + " " + name + " " + wrap;
                        byte[] ours = kdf(JSL, name, a.getPrivate(), b.getPublic(), ukm, wrap);
                        byte[] ref = kdf(BC, entry[0], toBc(b.getPrivate()), toBc(a.getPublic()), ukm, wrap);
                        Assertions.assertArrayEquals(ref, ours, label);
                        byte[] ukm2 = Arrays.clone(ukm);
                        ukm2[0] ^= 1;
                        Assertions.assertFalse(
                                Arrays.areEqual(ours, kdf(JSL, name, a.getPrivate(), b.getPublic(), ukm2, wrap)),
                                label + ": the UKM must change the KEK");
                        checked++;
                    }
                }
            }
        }
        Assertions.assertEquals(2 * 5 * 2 * 3, checked, "every curve, name, OID and KEK length must be driven");
    }

    /** On a cofactor curve the KDF over cofactor ECDH differs from the KDF over plain ECDH. */
    @Test
    public void cofactorKdfDiffersFromPlainKdfOnACofactorCurve() throws Exception
    {
        KeyPair a = generate("sect233k1");
        KeyPair b = generate("sect233k1");
        byte[] ukm = new byte[16];
        RANDOM.nextBytes(ukm);
        byte[] cofactor = kdf(JSL, "ECCDHWITHSHA256KDF", a.getPrivate(), b.getPublic(), ukm, WRAP_OIDS[0]);
        byte[] plain = kdf(JSL, "ECDHWITHSHA256KDF", a.getPrivate(), b.getPublic(), ukm, WRAP_OIDS[0]);
        Assertions.assertFalse(Arrays.areEqual(cofactor, plain));
        Assertions.assertArrayEquals(
                kdf(BC, "ECDHWITHSHA256KDF", toBc(a.getPrivate()), toBc(b.getPublic()), ukm, WRAP_OIDS[0]), plain);
    }

    /** The RFC 6637 CKDF names, which BouncyCastle computes over cofactor ECDH. */
    private static final String[][] CKDF_NAMES = {
        {"ECCDHwithSHA256CKDF", "SHA-256"}, {"ECCDHwithSHA384CKDF", "SHA-384"}, {"ECCDHwithSHA512CKDF", "SHA-512"}};

    /** BouncyCastle's one-step KDF over a given Z, as its agreement applies it: KDFParameters(Z, UKM). */
    private static byte[] concatenationKdf(String digest, byte[] z, byte[] ukm, int len)
    {
        ConcatenationKDFGenerator gen = new ConcatenationKDFGenerator("SHA-256".equals(digest) ? new SHA256Digest()
                : "SHA-384".equals(digest) ? new SHA384Digest() : new SHA512Digest());
        gen.init(new KDFParameters(z, ukm));
        byte[] out = new byte[len];
        gen.generateBytes(out, 0, len);
        return out;
    }

    /**
     * The CKDF names are cofactor ECDH: on sect233k1 each agrees with BouncyCastle's same name and differs from the
     * same KDF over plain ECDH; on P-256 it is the same KDF over plain ECDH, as before the switch.
     */
    @Test
    public void ckdfNamesRunOverCofactorEcdh() throws Exception
    {
        for (String curve : new String[]{"sect233k1", "P-256"})
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            byte[] plainZ = raw(JSL, "ECDH", a.getPrivate(), b.getPublic());
            byte[] cofactorZ = raw(JSL, "ECCDH", a.getPrivate(), b.getPublic());
            for (String[] entry : CKDF_NAMES)
            {
                byte[] ukm = new byte[1 + RANDOM.nextInt(64)];
                RANDOM.nextBytes(ukm);
                String label = curve + " " + entry[0];
                byte[] ours = kdf(JSL, entry[0], a.getPrivate(), b.getPublic(), ukm, WRAP_OIDS[2]);
                Assertions.assertArrayEquals(kdf(BC, entry[0], toBc(b.getPrivate()), toBc(a.getPublic()), ukm,
                        WRAP_OIDS[2]), ours, label);
                Assertions.assertArrayEquals(concatenationKdf(entry[1], cofactorZ, ukm, 32), ours,
                        label + ": the KDF over cofactor Z");
                boolean prime = !curve.startsWith("sect");
                Assertions.assertEquals(prime, Arrays.areEqual(concatenationKdf(entry[1], plainZ, ukm, 32), ours),
                        label + (prime ? ": cofactor 1 must equal the KDF over plain Z" : ": must differ from it"));
            }
        }
    }

    /** A re-initialised instance stays in cofactor mode: the native ctx is replaced by every init. */
    @Test
    public void aReinitialisedInstanceStaysInCofactorMode() throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("ECCDH", JSL);
        for (int t = 0; t < TRIALS; t++)
        {
            KeyPair a = generate("sect233k1");
            KeyPair b = generate("sect233k1");
            ka.init(a.getPrivate());
            KeyAgreementCalls.phase(ka, b.getPublic());
            Assertions.assertArrayEquals(raw(BC, "ECCDH", toBc(a.getPrivate()), toBc(b.getPublic())),
                    KeyAgreementCalls.secret(ka), "init " + t);
        }
    }

    /** Every name and OID resolves on JSL as it does on BouncyCastle 1.87, and to the same SPI per family. */
    @Test
    public void theNamesAndOidsAreServedAsBouncyCastleServesThem()
    {
        Provider jsl = Security.getProvider(JSL);
        Provider bc = Security.getProvider(BC);
        for (String name : RAW_NAMES)
        {
            Assertions.assertNotNull(bc.getService("KeyAgreement", name), "BouncyCastle " + name);
            Assertions.assertNotNull(jsl.getService("KeyAgreement", name), name);
        }
        Assertions.assertEquals(jsl.getService("KeyAgreement", "ECCDH").getClassName(),
                jsl.getService("KeyAgreement", "ECDHC").getClassName());
        for (String[] entry : KDF_NAMES)
        {
            for (String name : entry)
            {
                Assertions.assertNotNull(bc.getService("KeyAgreement", name), "BouncyCastle " + name);
                Assertions.assertNotNull(jsl.getService("KeyAgreement", name), name);
            }
        }
    }
}
