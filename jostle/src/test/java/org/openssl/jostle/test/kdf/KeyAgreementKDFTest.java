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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.kdf.KeyAgreementKDF;
import org.openssl.jostle.util.Arrays;

import java.security.SecureRandom;

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

    // Wrap OIDs and their KEK byte lengths.
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5",   // aes128-wrap -> 16
            "2.16.840.1.101.3.4.1.25",  // aes192-wrap -> 24
            "2.16.840.1.101.3.4.1.45",  // aes256-wrap -> 32
            "1.2.840.113549.1.9.16.3.6" // 3des-wrap   -> 24
    };

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
}
