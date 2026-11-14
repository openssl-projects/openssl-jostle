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

package org.openssl.jostle.test.fips;

import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
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

/**
 * The JSLFIPS half of ECCofactorAgreementTest: cofactor ECDH and its RFC 5753 KDF names agree with BouncyCastle 1.87
 * when the module does the work. A module that refuses plain ECDH on a cofactor curve must perform cofactor ECDH
 * there, which is what proves it honours the mode.
 */
public class FIPSECCofactorAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static final String[] PRIME_CURVES = {"P-256", "P-384", "P-521"};

    /** Cofactor 4 and 2, at 112 bits or more. */
    private static final String[] COFACTOR_CURVES = {"sect233k1", "sect233r1", "sect283k1"};

    private static final String[][] KDF_NAMES = {
        {"ECCDHWITHSHA1KDF", "1.3.133.16.840.63.0.3"},
        {"ECCDHWITHSHA224KDF", "1.3.132.1.14.0"},
        {"ECCDHWITHSHA256KDF", "1.3.132.1.14.1"},
        {"ECCDHWITHSHA384KDF", "1.3.132.1.14.2"},
        {"ECCDHWITHSHA512KDF", "1.3.132.1.14.3"}};

    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static KeyPair generate(String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", FIPS);
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

    private static byte[] kdf(String provider, String name, PrivateKey priv, PublicKey peer, byte[] ukm)
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
        return KeyAgreementCalls.secret(ka, AES256_WRAP).getEncoded();
    }

    /** Cofactor 1: ECCDH and ECDHC agree with BouncyCastle and with plain ECDH. */
    @Test
    public void primeCurvesAgreeWithBouncyCastleAndWithPlainEcdh() throws Exception
    {
        for (String curve : PRIME_CURVES)
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            byte[] ref = raw(BC, "ECCDH", toBc(b.getPrivate()), toBc(a.getPublic()));
            for (String name : new String[]{"ECCDH", "ECDHC"})
            {
                Assertions.assertArrayEquals(ref, raw(FIPS, name, a.getPrivate(), b.getPublic()), curve + " " + name);
            }
            Assertions.assertArrayEquals(ref, raw(FIPS, "ECDH", a.getPrivate(), b.getPublic()), curve + " ECDH");
            Assertions.assertFalse(Arrays.areEqual(ref, raw(FIPS, "ECCDH", a.getPrivate(), generate(curve)
                    .getPublic())), curve + ": a new peer");
        }
    }

    /**
     * On a cofactor curve the module's cofactor ECDH matches BouncyCastle's and differs from plain ECDH. Where the
     * module refuses plain ECDH it must say to use cofactor ECDH, and the key must live in the "fips" provider.
     */
    @Test
    public void cofactorCurvesDeriveCofactorEcdhInTheModule() throws Exception
    {
        for (String curve : COFACTOR_CURVES)
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            PKEYKeySpec spec = ((OSSLKey) a.getPrivate()).getSpec();
            Assertions.assertEquals("fips", spec.getSpecNI().getKeyProvider(spec.getReference()), curve);

            byte[] ours = raw(FIPS, "ECCDH", a.getPrivate(), b.getPublic());
            Assertions.assertArrayEquals(raw(BC, "ECCDH", toBc(b.getPrivate()), toBc(a.getPublic())), ours, curve);

            byte[] plain;
            try
            {
                plain = raw(FIPS, "ECDH", a.getPrivate(), b.getPublic());
            }
            catch (ProviderCapabilityException e)
            {
                Assertions.assertEquals("ECDH on a curve with cofactor != 1 requires cofactor ECDH under the loaded"
                        + " provider; use the ECCDH KeyAgreement", e.getMessage(), curve);
                continue;
            }
            Assertions.assertFalse(Arrays.areEqual(ours, plain), curve + ": cofactor above 1 must differ from ECDH");
        }
    }

    /** Every KDF name and OID agrees with BouncyCastle on a prime and a cofactor curve; the UKM changes the KEK. */
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
                    byte[] ukm = new byte[1 + RANDOM.nextInt(64)];
                    RANDOM.nextBytes(ukm);
                    byte[] ours = kdf(FIPS, name, a.getPrivate(), b.getPublic(), ukm);
                    Assertions.assertArrayEquals(kdf(BC, entry[0], toBc(b.getPrivate()), toBc(a.getPublic()), ukm),
                            ours, curve + " " + name);
                    ukm[0] ^= 1;
                    Assertions.assertFalse(Arrays.areEqual(ours, kdf(FIPS, name, a.getPrivate(), b.getPublic(), ukm)),
                            curve + " " + name + ": the UKM must change the KEK");
                    checked++;
                }
            }
        }
        Assertions.assertEquals(2 * 5 * 2, checked, "every curve, name and OID must be driven");
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
     * The CKDF names run over the module's cofactor ECDH: on a cofactor curve each agrees with BouncyCastle's same
     * name and differs from the same KDF over plain ECDH; on P-256 it is the KDF over plain ECDH, as before.
     */
    @Test
    public void ckdfNamesRunOverCofactorEcdh() throws Exception
    {
        for (String curve : new String[]{"sect233k1", "sect283k1", "P-256"})
        {
            KeyPair a = generate(curve);
            KeyPair b = generate(curve);
            byte[] plainZ = raw(BC, "ECDH", toBc(a.getPrivate()), toBc(b.getPublic()));
            byte[] cofactorZ = raw(FIPS, "ECCDH", a.getPrivate(), b.getPublic());
            for (String[] entry : CKDF_NAMES)
            {
                byte[] ukm = new byte[1 + RANDOM.nextInt(64)];
                RANDOM.nextBytes(ukm);
                String label = curve + " " + entry[0];
                byte[] ours = kdf(FIPS, entry[0], a.getPrivate(), b.getPublic(), ukm);
                Assertions.assertArrayEquals(kdf(BC, entry[0], toBc(b.getPrivate()), toBc(a.getPublic()), ukm), ours,
                        label);
                Assertions.assertArrayEquals(concatenationKdf(entry[1], cofactorZ, ukm, 32), ours,
                        label + ": the KDF over cofactor Z");
                boolean prime = !curve.startsWith("sect");
                Assertions.assertEquals(prime, Arrays.areEqual(concatenationKdf(entry[1], plainZ, ukm, 32), ours),
                        label + (prime ? ": cofactor 1 must equal the KDF over plain Z" : ": must differ from it"));
            }
        }
    }

    /** The names and OIDs are served by JSLFIPS, ECDHC to the ECCDH SPI. */
    @Test
    public void theNamesAndOidsAreServed()
    {
        Provider fips = Security.getProvider(FIPS);
        Assertions.assertEquals(fips.getService("KeyAgreement", "ECCDH").getClassName(),
                fips.getService("KeyAgreement", "ECDHC").getClassName());
        for (String[] entry : KDF_NAMES)
        {
            for (String name : entry)
            {
                Assertions.assertNotNull(fips.getService("KeyAgreement", name), name);
            }
        }
    }
}
