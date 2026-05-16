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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.HKDFKeySpec;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * HKDF (RFC 5869) tests. Covers:
 * <ol>
 *   <li>RFC 5869 KAT vectors for SHA-256 (Test Cases 1–3) and SHA-1
 *       (Test Cases 4–7) — these are the canonical regression set
 *       and exercise both populated and empty salt/info paths.</li>
 *   <li>Per-PRF transformation lookups (HKDFwithHmacSHA256, SHA384,
 *       SHA512, SHA1) and rejection of a digest mismatch when the
 *       transformation pins one.</li>
 *   <li>Negative input validation at the {@link HKDFKeySpec}
 *       constructor (null IKM, empty IKM, zero output length).</li>
 * </ol>
 *
 * <p>HKDF is the modern KDF used by every TLS 1.3 / CMS-KEM / CMP
 * recipient-info path; CMP's RFC 9629 key-transport-with-KEM profile
 * depends on it directly.
 */
public class HKDFTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    // -----------------------------------------------------------------
    // RFC 5869 KAT vectors — Appendix A
    // -----------------------------------------------------------------

    /** RFC 5869 §A.1: Test Case 1 — Basic test case with SHA-256. */
    @Test
    public void rfc5869_TestCase1_sha256() throws Exception
    {
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        int outLen = 42;
        byte[] expectedOKM = Hex.decode(
                "3cb25f25faacd57a90434f64d0362f2a"
                        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865");

        assertHKDF("HKDFwithHmacSHA256", ikm, salt, info, outLen, expectedOKM);
    }

    /** RFC 5869 §A.2: Test Case 2 — Longer inputs / outputs with SHA-256. */
    @Test
    public void rfc5869_TestCase2_sha256() throws Exception
    {
        byte[] ikm = Hex.decode(
                "000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f"
                        + "202122232425262728292a2b2c2d2e2f"
                        + "303132333435363738393a3b3c3d3e3f"
                        + "404142434445464748494a4b4c4d4e4f");
        byte[] salt = Hex.decode(
                "606162636465666768696a6b6c6d6e6f"
                        + "707172737475767778797a7b7c7d7e7f"
                        + "808182838485868788898a8b8c8d8e8f"
                        + "909192939495969798999a9b9c9d9e9f"
                        + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = Hex.decode(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                        + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                        + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                        + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        int outLen = 82;
        byte[] expectedOKM = Hex.decode(
                "b11e398dc80327a1c8e7f78c596a4934"
                        + "4f012eda2d4efad8a050cc4c19afa97c"
                        + "59045a99cac7827271cb41c65e590e09"
                        + "da3275600c2f09b8367793a9aca3db71"
                        + "cc30c58179ec3e87c14c01d5c1f3434f"
                        + "1d87");

        assertHKDF("HKDFwithHmacSHA256", ikm, salt, info, outLen, expectedOKM);
    }

    /** RFC 5869 §A.3: Test Case 3 — SHA-256 with empty salt and info. */
    @Test
    public void rfc5869_TestCase3_sha256_emptySaltInfo() throws Exception
    {
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = new byte[0];
        byte[] info = new byte[0];
        int outLen = 42;
        byte[] expectedOKM = Hex.decode(
                "8da4e775a563c18f715f802a063c5a31"
                        + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8");

        assertHKDF("HKDFwithHmacSHA256", ikm, salt, info, outLen, expectedOKM);
    }

    /** RFC 5869 §A.4: Test Case 4 — Basic SHA-1. */
    @Test
    public void rfc5869_TestCase4_sha1() throws Exception
    {
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        int outLen = 42;
        byte[] expectedOKM = Hex.decode(
                "085a01ea1b10f36933068b56efa5ad81"
                        + "a4f14b822f5b091568a9cdd4f155fda2"
                        + "c22e422478d305f3f896");

        assertHKDF("HKDFwithHmacSHA1", ikm, salt, info, outLen, expectedOKM);
    }

    /** RFC 5869 §A.5: Test Case 5 — Longer SHA-1 inputs / outputs. */
    @Test
    public void rfc5869_TestCase5_sha1() throws Exception
    {
        byte[] ikm = Hex.decode(
                "000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f"
                        + "202122232425262728292a2b2c2d2e2f"
                        + "303132333435363738393a3b3c3d3e3f"
                        + "404142434445464748494a4b4c4d4e4f");
        byte[] salt = Hex.decode(
                "606162636465666768696a6b6c6d6e6f"
                        + "707172737475767778797a7b7c7d7e7f"
                        + "808182838485868788898a8b8c8d8e8f"
                        + "909192939495969798999a9b9c9d9e9f"
                        + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = Hex.decode(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                        + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                        + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                        + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        int outLen = 82;
        byte[] expectedOKM = Hex.decode(
                "0bd770a74d1160f7c9f12cd5912a06eb"
                        + "ff6adcae899d92191fe4305673ba2ffe"
                        + "8fa3f1a4e5ad79f3f334b3b202b2173c"
                        + "486ea37ce3d397ed034c7f9dfeb15c5e"
                        + "927336d0441f4c4300e2cff0d0900b52"
                        + "d3b4");

        assertHKDF("HKDFwithHmacSHA1", ikm, salt, info, outLen, expectedOKM);
    }

    /** RFC 5869 §A.6: Test Case 6 — SHA-1 with empty salt and info. */
    @Test
    public void rfc5869_TestCase6_sha1_emptySaltInfo() throws Exception
    {
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = new byte[0];
        byte[] info = new byte[0];
        int outLen = 42;
        byte[] expectedOKM = Hex.decode(
                "0ac1af7002b3d761d1e55298da9d0506"
                        + "b9ae52057220a306e07b6b87e8df21d0"
                        + "ea00033de03984d34918");

        assertHKDF("HKDFwithHmacSHA1", ikm, salt, info, outLen, expectedOKM);
    }

    /**
     * RFC 5869 §A.7: Test Case 7 — null salt (interpreted as a zero-byte
     * string per the RFC), null info, IKM is the constant 0x0c bytes.
     * Exercises the salt=null path through our SPI.
     */
    @Test
    public void rfc5869_TestCase7_sha1_nullSaltInfo() throws Exception
    {
        byte[] ikm = Hex.decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
        byte[] salt = null;
        byte[] info = null;
        int outLen = 42;
        byte[] expectedOKM = Hex.decode(
                "2c91117204d745f3500d636a62f64f0a"
                        + "b3bae548aa53d423b0d1f27ebba6f5e5"
                        + "673a081d70cce7acfc48");

        assertHKDF("HKDFwithHmacSHA1", ikm, salt, info, outLen, expectedOKM);
    }


    // -----------------------------------------------------------------
    // SHA-384 / SHA-512 roundtrip + cross-PRF mismatch rejection
    // -----------------------------------------------------------------

    @Test
    public void hkdf_sha384_roundTrip() throws Exception
    {
        byte[] ikm = Hex.decode("0102030405060708090a0b0c0d0e0f10");
        byte[] salt = Hex.decode("aabbccdd");
        byte[] info = Hex.decode("c0ffee");
        int outLen = 48; // SHA-384 hash size

        SecretKey one = derive("HKDFwithHmacSHA384", ikm, salt, info, outLen, "SHA-384");
        SecretKey two = derive("HKDFwithHmacSHA384", ikm, salt, info, outLen, "SHA-384");
        Assertions.assertArrayEquals(one.getEncoded(), two.getEncoded(),
                "HKDF-SHA384 should be deterministic for the same inputs");
        Assertions.assertEquals(outLen, one.getEncoded().length);
    }

    @Test
    public void hkdf_sha512_roundTrip() throws Exception
    {
        byte[] ikm = Hex.decode("0102030405060708090a0b0c0d0e0f10");
        byte[] salt = Hex.decode("aabbccdd");
        byte[] info = Hex.decode("c0ffee");
        int outLen = 64; // SHA-512 hash size

        SecretKey one = derive("HKDFwithHmacSHA512", ikm, salt, info, outLen, "SHA-512");
        SecretKey two = derive("HKDFwithHmacSHA512", ikm, salt, info, outLen, "SHA-512");
        Assertions.assertArrayEquals(one.getEncoded(), two.getEncoded(),
                "HKDF-SHA512 should be deterministic for the same inputs");
        Assertions.assertEquals(outLen, one.getEncoded().length);
    }

    @Test
    public void hkdf_bareHKDF_acceptsAnyPRF() throws Exception
    {
        // The bare HKDF registration has no forced digest; the spec's
        // digest drives the call.
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
        byte[] expectedOKM = Hex.decode(
                "3cb25f25faacd57a90434f64d0362f2a"
                        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865");

        SecretKeyFactory kf = SecretKeyFactory.getInstance("HKDF", JostleProvider.PROVIDER_NAME);
        HKDFKeySpec spec = new HKDFKeySpec(ikm, salt, info, 42, "SHA-256");
        SecretKey sk = kf.generateSecret(spec);

        Assertions.assertArrayEquals(expectedOKM, sk.getEncoded());
    }

    @Test
    public void hkdf_digestMismatch_rejected() throws Exception
    {
        // HKDFwithHmacSHA256 pinned at construction; spec says SHA-384.
        SecretKeyFactory kf = SecretKeyFactory.getInstance("HKDFwithHmacSHA256", JostleProvider.PROVIDER_NAME);
        HKDFKeySpec spec = new HKDFKeySpec(new byte[]{1, 2, 3}, null, null, 32, "SHA-384");
        try
        {
            kf.generateSecret(spec);
            Assertions.fail("expected InvalidKeySpecException for PRF mismatch");
        }
        catch (InvalidKeySpecException expected)
        {
            Assertions.assertNotNull(expected.getMessage());
            Assertions.assertTrue(expected.getMessage().contains("does not match forced PRF"),
                    "unexpected message: " + expected.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // HKDFKeySpec constructor negative paths
    // -----------------------------------------------------------------

    @Test
    public void hkdfKeySpec_nullIKM_rejected()
    {
        try
        {
            new HKDFKeySpec(null, null, null, 32, "SHA-256");
            Assertions.fail("expected IllegalArgumentException for null IKM");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("ikm is null", expected.getMessage());
        }
    }

    @Test
    public void hkdfKeySpec_emptyIKM_rejected()
    {
        try
        {
            new HKDFKeySpec(new byte[0], null, null, 32, "SHA-256");
            Assertions.fail("expected IllegalArgumentException for empty IKM");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("ikm is empty", expected.getMessage());
        }
    }

    @Test
    public void hkdfKeySpec_zeroOutLength_rejected()
    {
        try
        {
            new HKDFKeySpec(new byte[]{1, 2, 3}, null, null, 0, "SHA-256");
            Assertions.fail("expected IllegalArgumentException for zero output length");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("outLengthBytes must be positive", expected.getMessage());
        }
    }

    @Test
    public void hkdfKeySpec_nullDigest_rejected()
    {
        try
        {
            new HKDFKeySpec(new byte[]{1, 2, 3}, null, null, 32, null);
            Assertions.fail("expected IllegalArgumentException for null digest");
        }
        catch (IllegalArgumentException expected)
        {
            Assertions.assertEquals("digestAlgorithm is null", expected.getMessage());
        }
    }

    @Test
    public void hkdf_unknownTransformation_throwsNoSuchAlgorithm() throws Exception
    {
        try
        {
            SecretKeyFactory.getInstance("HKDFwithHmacSomethingMadeUp", JostleProvider.PROVIDER_NAME);
            Assertions.fail("expected NoSuchAlgorithmException");
        }
        catch (NoSuchAlgorithmException expected)
        {
            // Good — JCE rejected the unknown transformation name.
        }
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static void assertHKDF(String xform, byte[] ikm, byte[] salt, byte[] info,
                                   int outLen, byte[] expectedOKM) throws Exception
    {
        String digest = xform.endsWith("SHA1") ? "SHA-1"
                : xform.endsWith("SHA224") ? "SHA-224"
                : xform.endsWith("SHA256") ? "SHA-256"
                : xform.endsWith("SHA384") ? "SHA-384"
                : xform.endsWith("SHA512") ? "SHA-512"
                : null;
        if (digest == null)
        {
            Assertions.fail("test helper doesn't know how to derive digest name from " + xform);
        }
        SecretKey sk = derive(xform, ikm, salt, info, outLen, digest);
        Assertions.assertArrayEquals(expectedOKM, sk.getEncoded(),
                xform + ": derived OKM did not match RFC vector");
    }

    private static SecretKey derive(String xform, byte[] ikm, byte[] salt, byte[] info,
                                    int outLen, String digest) throws Exception
    {
        SecretKeyFactory kf = SecretKeyFactory.getInstance(xform, JostleProvider.PROVIDER_NAME);
        KeySpec spec = new HKDFKeySpec(ikm, salt, info, outLen, digest);
        return kf.generateSecret(spec);
    }
}
