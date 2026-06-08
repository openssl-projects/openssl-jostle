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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Coverage for IV/AEAD parameter handling in {@code BlockCipherSpi}:
 * <ul>
 *   <li>{@code engineInit(opmode, key, random)} auto-generates an IV/nonce for
 *       encryption when no parameters are supplied (12 bytes for GCM, block size
 *       for CBC), as the JCE contract and CMS require;</li>
 *   <li>{@code engineGetIV()} and {@code engineGetParameters()} report the IV in
 *       effect (including the auto-generated one) — previously both threw
 *       "not implemented";</li>
 *   <li>the generated parameters round-trip for decryption, both within JSL and
 *       across to BouncyCastle, asserting wire portability;</li>
 *   <li>ECB exposes no parameters;</li>
 *   <li>decryption initialised from an {@link AlgorithmParameters} works for GCM
 *       (the path CMS uses on the receiving side).</li>
 * </ul>
 */
public class AESParametersTest
{
    private static final String GCM = "AES/GCM/NoPadding";
    private static final String CBC = "AES/CBC/NoPadding";
    private static final String ECB = "AES/ECB/NoPadding";
    private static final String AES256_GCM_OID = "2.16.840.1.101.3.4.1.46";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecretKey aes256Key(SecureRandom random)
    {
        byte[] key = new byte[32];
        random.nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    @Test
    public void gcmEncryptWithoutParamsAutoGeneratesIv() throws Exception
    {
        SecureRandom random = seededRandom("gcmEncryptWithoutParamsAutoGeneratesIv");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[40];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random);     // no parameters supplied

        byte[] iv = enc.getIV();
        Assertions.assertNotNull(iv, "GCM must expose an auto-generated IV");
        Assertions.assertEquals(12, iv.length, "GCM nonce must be 12 bytes");

        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params, "GCM must expose auto-generated AlgorithmParameters");
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertEquals(128, spec.getTLen(), "default GCM tag length must be 128 bits");
        Assertions.assertArrayEquals(iv, spec.getIV(), "getIV() and getParameters() must agree");

        byte[] ct = enc.doFinal(msg);

        // decrypt within JSL using the recovered parameters
        Cipher dec = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "round-trip via getParameters() failed");
    }

    @Test
    public void gcmAutoIvViaOidTransformation() throws Exception
    {
        SecureRandom random = seededRandom("gcmAutoIvViaOidTransformation");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[33];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(AES256_GCM_OID, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random);
        Assertions.assertEquals(12, enc.getIV().length);
        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params);
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance(AES256_GCM_OID, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    @Test
    public void gcmParametersInteropWithBouncyCastle() throws Exception
    {
        SecureRandom random = seededRandom("gcmParametersInteropWithBouncyCastle");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[64];
        random.nextBytes(msg);

        // JSL encrypts with an auto-generated IV; BouncyCastle decrypts using
        // the parameters JSL produced — exercises the encoded GCM parameters.
        Cipher jslEnc = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        jslEnc.init(Cipher.ENCRYPT_MODE, key, random);
        byte[] ct = jslEnc.doFinal(msg);
        AlgorithmParameters jslParams = jslEnc.getParameters();

        Cipher bcDec = Cipher.getInstance(GCM, BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, key, jslParams);
        Assertions.assertArrayEquals(msg, bcDec.doFinal(ct), "BC could not decrypt using JSL's GCM parameters");

        // Reverse: BouncyCastle auto-generates the IV, JSL decrypts using BC's parameters.
        Cipher bcEnc = Cipher.getInstance(GCM, BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, key, random);
        byte[] ct2 = bcEnc.doFinal(msg);
        AlgorithmParameters bcParams = bcEnc.getParameters();

        Cipher jslDec = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        jslDec.init(Cipher.DECRYPT_MODE, key, bcParams);
        Assertions.assertArrayEquals(msg, jslDec.doFinal(ct2), "JSL could not decrypt using BC's GCM parameters");
    }

    @Test
    public void cbcEncryptWithoutParamsAutoGeneratesIv() throws Exception
    {
        SecureRandom random = seededRandom("cbcEncryptWithoutParamsAutoGeneratesIv");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[48]; // exact block multiple for NoPadding
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random);     // no parameters supplied

        byte[] iv = enc.getIV();
        Assertions.assertNotNull(iv, "CBC must expose an auto-generated IV");
        Assertions.assertEquals(16, iv.length, "CBC IV must be one AES block");

        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params, "CBC must expose auto-generated AlgorithmParameters");
        Assertions.assertArrayEquals(iv, params.getParameterSpec(IvParameterSpec.class).getIV());

        byte[] ct = enc.doFinal(msg);

        // interop: BouncyCastle decrypts using JSL's IV
        Cipher bcDec = Cipher.getInstance(CBC, BouncyCastleProvider.PROVIDER_NAME);
        bcDec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(msg, bcDec.doFinal(ct));
    }

    @Test
    public void ecbExposesNoParameters() throws Exception
    {
        SecureRandom random = seededRandom("ecbExposesNoParameters");
        SecretKey key = aes256Key(random);

        Cipher enc = Cipher.getInstance(ECB, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random);

        Assertions.assertNull(enc.getIV(), "ECB has no IV");
        Assertions.assertNull(enc.getParameters(), "ECB has no parameters");
    }

    @Test
    public void gcmDecryptInitialisedFromAlgorithmParameters() throws Exception
    {
        SecureRandom random = seededRandom("gcmDecryptInitialisedFromAlgorithmParameters");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[20];
        random.nextBytes(msg);

        byte[] iv = new byte[12];
        random.nextBytes(iv);
        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
        params.init(new GCMParameterSpec(128, iv));

        Cipher enc = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ct = enc.doFinal(msg);

        // The receiving side (as CMS does) initialises purely from AlgorithmParameters.
        Cipher dec = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    @Test
    public void gcmDecryptWithWrongIvFails() throws Exception
    {
        SecureRandom random = seededRandom("gcmDecryptWithWrongIvFails");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[24];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random);
        byte[] ct = enc.doFinal(msg);
        byte[] iv = enc.getIV();

        byte[] wrongIv = Arrays.clone(iv);
        wrongIv[0] ^= 0x01;

        Cipher dec = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, wrongIv));
        boolean rejected = false;
        try
        {
            dec.doFinal(ct);
        }
        catch (Exception e)
        {
            rejected = true;
        }
        Assertions.assertTrue(rejected, "GCM must reject decryption under the wrong nonce");
    }

    @Test
    public void gcmEncryptCannotBeReusedWithoutReinit() throws Exception
    {
        SecureRandom random = seededRandom("gcmEncryptCannotBeReusedWithoutReinit");
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[29];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, random);
        enc.doFinal(msg);

        // A second GCM encryption on the same instance would reuse the
        // auto-generated nonce (catastrophic) and must be rejected until
        // re-init — SunJCE's "Cannot reuse" contract.
        boolean rejected = false;
        try
        {
            enc.doFinal(msg);
        }
        catch (IllegalStateException e)
        {
            rejected = true;
        }
        Assertions.assertTrue(rejected, "GCM encrypt reuse without re-init must throw IllegalStateException");

        // Re-init draws a fresh nonce; the instance is usable again and the
        // result decrypts cleanly.
        enc.init(Cipher.ENCRYPT_MODE, key, random);
        byte[] ct = enc.doFinal(msg);
        byte[] iv = enc.getIV();
        Cipher dec = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "instance must be reusable after re-init");
    }

    @Test
    public void gcmRejectsMalformedTagLength() throws Exception
    {
        SecureRandom random = seededRandom("gcmRejectsMalformedTagLength");
        SecretKey key = aes256Key(random);
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        // Out-of-range and non-multiple-of-8 tag lengths are rejected at the JCE
        // boundary with the contracted exception type, rather than reaching
        // OpenSSL: 24/8 are below the BC floor, 100 is not byte-aligned, 136 is
        // above the 128-bit maximum.
        for (int badBits : new int[]{8, 24, 100, 136})
        {
            Cipher c = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
            boolean rejected = false;
            try
            {
                c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(badBits, iv), random);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                rejected = true;
            }
            Assertions.assertTrue(rejected, "malformed GCM tag length " + badBits + " must be rejected");
        }

        // The BC-compatible boundary values are accepted.
        for (int okBits : new int[]{32, 128})
        {
            Cipher c = Cipher.getInstance(GCM, JostleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(okBits, iv), random);
            Assertions.assertNotNull(c.getIV(), okBits + "-bit GCM tag must be accepted");
        }
    }
}
