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

import org.openssl.jostle.jcajce.spec.ScryptKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
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
    private static final String AES128_CBC_OID = "2.16.840.1.101.3.4.1.2";
    private static final String AES192_CBC_OID = "2.16.840.1.101.3.4.1.22";
    private static final String AES256_CBC_OID = "2.16.840.1.101.3.4.1.42";

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
    public void cbcAlgorithmParametersResolveByOid() throws Exception
    {
        // The decrypt-side path BC's PBES2 / PKCS#8 / PKCS#12 decryptors take:
        // resolve AES-CBC parameters by OID through JSL to recover the stored IV.
        // All three AES-CBC OIDs (128/192/256) must resolve and codec the IV.
        SecureRandom random = seededRandom("cbcAlgorithmParametersResolveByOid");

        for (String oid : new String[]{AES128_CBC_OID, AES192_CBC_OID, AES256_CBC_OID})
        {
            byte[] iv = new byte[16];
            random.nextBytes(iv);

            AlgorithmParameters params = AlgorithmParameters.getInstance(oid, JostleProvider.PROVIDER_NAME);
            params.init(new IvParameterSpec(iv));

            // Encode → decode round-trip (the IV OCTET STRING) preserves the IV.
            byte[] encoded = params.getEncoded();
            AlgorithmParameters reparsed = AlgorithmParameters.getInstance(oid, JostleProvider.PROVIDER_NAME);
            reparsed.init(encoded);
            Assertions.assertArrayEquals(iv, reparsed.getParameterSpec(IvParameterSpec.class).getIV(),
                    oid + ": AES-CBC AlgorithmParameters did not round-trip the IV");

            // The encoded form must be portable: BouncyCastle parses JSL's encoding.
            AlgorithmParameters bcParams = AlgorithmParameters.getInstance(oid, BouncyCastleProvider.PROVIDER_NAME);
            bcParams.init(encoded);
            Assertions.assertArrayEquals(iv, bcParams.getParameterSpec(IvParameterSpec.class).getIV(),
                    oid + ": BC could not parse JSL's AES-CBC parameter encoding");

            // ...and the resolved parameters drive a real CBC decrypt (init purely
            // from AlgorithmParameters, as the PBES2 receiving side does). The IV
            // size is independent of the OID's key size, so a 256-bit key is fine.
            SecretKey key = aes256Key(random);
            byte[] msg = new byte[48];
            random.nextBytes(msg);
            Cipher enc = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
            enc.init(Cipher.ENCRYPT_MODE, key, params);
            byte[] ct = enc.doFinal(msg);

            Cipher dec = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
            dec.init(Cipher.DECRYPT_MODE, key, reparsed);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                    oid + ": CBC decrypt initialised from AlgorithmParameters failed");
        }
    }

    @Test
    public void cbcAcceptsKdfDerivedKeys() throws Exception
    {
        // PBES2 / PKCS#8 hands a KDF-derived key straight to the cipher; the
        // cipher must accept it despite its non-"AES" algorithm name
        // (CBC_AUTO_IV_GAP item 2 — validateKeyAlg now accepts PBEKeys).
        SecureRandom random = seededRandom("cbcAcceptsKdfDerivedKeys");
        byte[] msg = new byte[48];
        random.nextBytes(msg);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        char[] pwd = "password".toCharArray();

        // scrypt-derived key (JOScryptKey, algorithm "ScryptWithUTF8") → AES-256.
        SecretKey scryptKey = SecretKeyFactory.getInstance("SCRYPT", JostleProvider.PROVIDER_NAME)
                .generateSecret(new ScryptKeySpec(pwd, salt, 1024, 8, 1, 256));
        Assertions.assertFalse("AES".equalsIgnoreCase(scryptKey.getAlgorithm()),
                "precondition: scrypt-derived key is not AES-named");
        cbcRoundTrip(scryptKey, iv, msg);

        // PBKDF2-derived key (JOPBEKey).
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", JostleProvider.PROVIDER_NAME)
                .generateSecret(new PBEKeySpec(pwd, salt, 4096, 256));
        cbcRoundTrip(pbeKey, iv, msg);
    }

    private static void cbcRoundTrip(SecretKey key, byte[] iv, byte[] msg) throws Exception
    {
        Cipher enc = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));   // must not throw "unsupported key algorithm"
        byte[] ct = enc.doFinal(msg);
        Cipher dec = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "round-trip with KDF-derived key failed");
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

    /**
     * AES-GCM {@code AlgorithmParameters} must now resolve from JSL by the bare
     * name "GCM" (not just by OID) — the lookup a JSL-bound BC helper performs
     * via {@code createAlgorithmParameters("GCM")}. Constructing it must NOT
     * recurse (the delegate is resolved from a non-Jostle provider), the IV/tag
     * must round-trip, and the encoding must interoperate with BouncyCastle.
     */
    @Test
    public void gcmAlgorithmParametersResolveByName() throws Exception
    {
        SecureRandom random = seededRandom("gcmAlgorithmParametersResolveByName");
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", JostleProvider.PROVIDER_NAME);
        params.init(new GCMParameterSpec(128, iv));
        byte[] encoded = params.getEncoded();

        // Round-trip through JSL's bare-name "GCM".
        AlgorithmParameters reparsed = AlgorithmParameters.getInstance("GCM", JostleProvider.PROVIDER_NAME);
        reparsed.init(encoded);
        GCMParameterSpec spec = reparsed.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertArrayEquals(iv, spec.getIV(), "GCM name params did not round-trip the nonce");
        Assertions.assertEquals(128, spec.getTLen(), "GCM name params did not round-trip the tag length");

        // Encoding is portable: the platform GCM AlgorithmParameters (SunJCE,
        // which is what JSL delegates to) parses JSL's "GCM" encoding back to
        // the same nonce/tag.
        AlgorithmParameters platform = AlgorithmParameters.getInstance("GCM");
        platform.init(encoded);
        GCMParameterSpec platformSpec = platform.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertArrayEquals(iv, platformSpec.getIV(),
                "platform GCM could not parse JSL's bare-name GCM parameter encoding");
        Assertions.assertEquals(128, platformSpec.getTLen(),
                "platform GCM read a different tag length from JSL's encoding");
    }

    /**
     * AES-CCM {@code AlgorithmParameters} — JSL is the only provider that ships
     * one (no JDK provider does), so it codes RFC 5084 {@code CCMParameters}
     * itself. The encoding is pinned to known-answer DER vectors (the gold
     * standard for a hand-rolled codec): the {@code aes-ICVlen} INTEGER is
     * omitted at the DEFAULT of 12 bytes and present otherwise. Resolves both by
     * the bare name "CCM" and the AES-256-CCM OID.
     */
    @Test
    public void ccmAlgorithmParameters_rfc5084Encoding() throws Exception
    {
        // Fixed 12-byte nonce so the expected DER is deterministic.
        byte[] nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        byte[] octetString = {0x04, 0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};

        // SEQUENCE { OCTET STRING nonce }                 -- ICV 12 (DEFAULT, omitted)
        byte[] expectDefault = concat(new byte[]{0x30, 0x0e}, octetString);
        // SEQUENCE { OCTET STRING nonce, INTEGER 16 }     -- ICV 16, INTEGER present
        byte[] expect16 = concat(concat(new byte[]{0x30, 0x11}, octetString), new byte[]{0x02, 0x01, 0x10});
        // SEQUENCE { OCTET STRING nonce, INTEGER 8 }      -- ICV 8, INTEGER present
        byte[] expect8 = concat(concat(new byte[]{0x30, 0x11}, octetString), new byte[]{0x02, 0x01, 0x08});

        String aes256CcmOid = "2.16.840.1.101.3.4.1.47";
        for (String name : new String[]{"CCM", aes256CcmOid})
        {
            assertCcmEncoding(name, nonce, 96, expectDefault);   // 96-bit tag => 12-byte ICV (DEFAULT)
            assertCcmEncoding(name, nonce, 128, expect16);
            assertCcmEncoding(name, nonce, 64, expect8);
        }
    }

    private static void assertCcmEncoding(String name, byte[] nonce, int tagBits, byte[] expectedDer)
            throws Exception
    {
        AlgorithmParameters jsl = AlgorithmParameters.getInstance(name, JostleProvider.PROVIDER_NAME);
        jsl.init(new GCMParameterSpec(tagBits, nonce));
        byte[] der = jsl.getEncoded();
        Assertions.assertArrayEquals(expectedDer, der,
                name + " tagBits=" + tagBits + ": CCMParameters DER does not match the RFC 5084 vector");

        // Decode round-trip: a fresh instance parses the encoding back.
        AlgorithmParameters reparsed = AlgorithmParameters.getInstance(name, JostleProvider.PROVIDER_NAME);
        reparsed.init(der);
        GCMParameterSpec spec = reparsed.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertArrayEquals(nonce, spec.getIV(),
                name + " tagBits=" + tagBits + ": CCMParameters did not round-trip the nonce");
        Assertions.assertEquals(tagBits, spec.getTLen(),
                name + " tagBits=" + tagBits + ": CCMParameters did not round-trip the tag length");
    }

    /**
     * The CCM {@code AlgorithmParameters} resolved from JSL must drive a real
     * AES-CCM decrypt — init the cipher purely from the parsed
     * {@code AlgorithmParameters}, as an OID/params-driven receiver does.
     */
    @Test
    public void ccmAlgorithmParameters_driveCipher() throws Exception
    {
        SecureRandom random = seededRandom("ccmAlgorithmParameters_driveCipher");
        SecretKey key = aes256Key(random);
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        byte[] msg = new byte[40];
        random.nextBytes(msg);

        AlgorithmParameters params = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        params.init(new GCMParameterSpec(128, nonce));

        Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ct = enc.doFinal(msg);

        // Re-encode then re-parse the parameters to exercise the codec end-to-end.
        AlgorithmParameters reparsed = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        reparsed.init(params.getEncoded());

        Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, reparsed);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                "CCM decrypt initialised from AlgorithmParameters failed");
    }

    /**
     * Negative path for the hand-rolled RFC 5084 {@code CCMParameters} decoder:
     * malformed DER must be rejected with {@code IOException}, never silently
     * accepted (a parser that swallows any bytes would sail through a
     * positive-only KAT). Covers every rejection branch of the codec's reader.
     */
    @Test
    public void ccmAlgorithmParameters_rejectsMalformedEncodings() throws Exception
    {
        // OCTET STRING of a valid 12-byte nonce: 04 0C 00..0B
        byte[] octetString = {0x04, 0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        // A well-formed baseline (ICV default omitted): 30 0E <octetString>.
        byte[] valid = concat(new byte[]{0x30, 0x0e}, octetString);

        byte[][] malformed = {
                // wrong outer tag (SET 0x31 instead of SEQUENCE 0x30)
                concat(new byte[]{0x31, 0x0e}, octetString),
                // trailing byte after a complete CCMParameters
                concat(valid, new byte[]{0x00}),
                // truncated content: SEQUENCE claims 0x0e but only the OCTET STRING header follows
                {0x30, 0x0e, 0x04, 0x0c, 0x00, 0x01},
                // unsupported long-form length on the outer SEQUENCE
                concat(new byte[]{0x30, (byte) 0x81, 0x0e}, octetString),
                // wrong inner tag (INTEGER 0x02 where an OCTET STRING is required)
                concat(new byte[]{0x30, 0x0e}, concat(new byte[]{0x02, 0x0c}, java.util.Arrays.copyOfRange(octetString, 2, 14))),
                // nonce too short (4 bytes < CCM minimum of 7): 30 06 04 04 00 01 02 03
                {0x30, 0x06, 0x04, 0x04, 0x00, 0x01, 0x02, 0x03},
                // invalid ICV length (INTEGER 5 is not in {4,6,8,10,12,14,16})
                concat(concat(new byte[]{0x30, 0x11}, octetString), new byte[]{0x02, 0x01, 0x05}),
                // empty input
                new byte[0],
        };

        for (int i = 0; i < malformed.length; i++)
        {
            final byte[] bad = malformed[i];
            AlgorithmParameters params = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
            final int idx = i;
            Assertions.assertThrows(java.io.IOException.class, () -> params.init(bad),
                    "malformed CCMParameters encoding #" + idx + " must be rejected");
        }

        // Sanity: the baseline the malformed cases derive from IS accepted.
        AlgorithmParameters ok = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        ok.init(valid);
        Assertions.assertEquals(12, ok.getParameterSpec(GCMParameterSpec.class).getIV().length,
                "the well-formed baseline encoding must parse");
    }

    /**
     * Cross-provider agreement for the hand-rolled CCM codec: BouncyCastle
     * ships {@code AlgorithmParameters "CCM"}, so validate both directions per
     * ICV value — a wrong-but-self-consistent codec passes its own round-trip
     * but not this. The BC→JSL direction is what catches DEFAULT-omission
     * disagreements (BC may emit the explicit-default ICV INTEGER).
     */
    @Test
    public void ccmAlgorithmParameters_agreeWithBouncyCastle() throws Exception
    {
        SecureRandom random = seededRandom("ccmAlgorithmParameters_agreeWithBouncyCastle");

        for (int icvBytes : new int[]{8, 12, 16})
        {
            byte[] nonce = new byte[7 + random.nextInt(7)]; // 7..13
            random.nextBytes(nonce);
            int tagBits = icvBytes * 8;

            // JSL encodes → BC parses.
            AlgorithmParameters jsl = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
            jsl.init(new GCMParameterSpec(tagBits, nonce));
            AlgorithmParameters bc = AlgorithmParameters.getInstance("CCM", BouncyCastleProvider.PROVIDER_NAME);
            bc.init(jsl.getEncoded());
            GCMParameterSpec bcSpec = bc.getParameterSpec(GCMParameterSpec.class);
            Assertions.assertArrayEquals(nonce, bcSpec.getIV(),
                    "icv=" + icvBytes + ": BC read a different nonce from JSL's CCM encoding");
            Assertions.assertEquals(tagBits, bcSpec.getTLen(),
                    "icv=" + icvBytes + ": BC read a different ICV from JSL's CCM encoding");

            // BC encodes → JSL parses.
            AlgorithmParameters bcOut = AlgorithmParameters.getInstance("CCM", BouncyCastleProvider.PROVIDER_NAME);
            bcOut.init(new GCMParameterSpec(tagBits, nonce));
            AlgorithmParameters jslIn = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
            jslIn.init(bcOut.getEncoded());
            GCMParameterSpec jslSpec = jslIn.getParameterSpec(GCMParameterSpec.class);
            Assertions.assertArrayEquals(nonce, jslSpec.getIV(),
                    "icv=" + icvBytes + ": JSL read a different nonce from BC's CCM encoding");
            Assertions.assertEquals(tagBits, jslSpec.getTLen(),
                    "icv=" + icvBytes + ": JSL read a different ICV from BC's CCM encoding");
        }
    }

    /**
     * The motivating CBC use case is the REVERSE of {@code
     * cbcAlgorithmParametersResolveByOid}: JSL parsing IV bytes another
     * provider produced (BC's PBES2 / PKCS#8 / PKCS#12 decrypt side).
     */
    @Test
    public void cbcAlgorithmParameters_parseForeignEncoding() throws Exception
    {
        SecureRandom random = seededRandom("cbcAlgorithmParameters_parseForeignEncoding");
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // BC produces the encoding; JSL (by OID) parses it.
        AlgorithmParameters bc = AlgorithmParameters.getInstance(AES256_CBC_OID, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new IvParameterSpec(iv));
        AlgorithmParameters jsl = AlgorithmParameters.getInstance(AES256_CBC_OID, JostleProvider.PROVIDER_NAME);
        jsl.init(bc.getEncoded());
        Assertions.assertArrayEquals(iv, jsl.getParameterSpec(IvParameterSpec.class).getIV(),
                "JSL could not parse BC's AES-CBC parameter encoding");

        // ...and the parsed parameters drive a real decrypt of a BC ciphertext.
        SecretKey key = aes256Key(random);
        byte[] msg = new byte[48];
        random.nextBytes(msg);
        Cipher bcEnc = Cipher.getInstance(CBC, BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = bcEnc.doFinal(msg);

        Cipher jslDec = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
        jslDec.init(Cipher.DECRYPT_MODE, key, jsl);
        Assertions.assertArrayEquals(msg, jslDec.doFinal(ct),
                "CBC decrypt from a foreign-encoded IV failed");
    }

    /**
     * GCM bare-name params, reverse direction: JSL parses bytes the PLATFORM
     * produced (the existing name test only proves the platform parses JSL's).
     */
    @Test
    public void gcmAlgorithmParameters_parsePlatformEncoding() throws Exception
    {
        SecureRandom random = seededRandom("gcmAlgorithmParameters_parsePlatformEncoding");
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        AlgorithmParameters platform = AlgorithmParameters.getInstance("GCM");
        platform.init(new GCMParameterSpec(96, iv));

        AlgorithmParameters jsl = AlgorithmParameters.getInstance("GCM", JostleProvider.PROVIDER_NAME);
        jsl.init(platform.getEncoded());
        GCMParameterSpec spec = jsl.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertArrayEquals(iv, spec.getIV(), "JSL read a different nonce from the platform encoding");
        Assertions.assertEquals(96, spec.getTLen(), "JSL read a different tag length from the platform encoding");
    }

    /**
     * CCM nonce boundary probes at exactly min-1 / min / max / max+1 (7..13
     * valid), on BOTH the spec-init side and the DER decode side, plus the
     * invalid-ICV, null-nonce and wrong-type spec-init negatives the decode
     * tests can't reach.
     */
    @Test
    public void ccmAlgorithmParameters_boundariesAndSpecNegatives() throws Exception
    {
        SecureRandom random = seededRandom("ccmAlgorithmParameters_boundariesAndSpecNegatives");

        // Spec-init side: 6 rejected, 7 and 13 accepted, 14 rejected.
        for (int len : new int[]{7, 13})
        {
            byte[] nonce = new byte[len];
            random.nextBytes(nonce);
            AlgorithmParameters ok = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
            ok.init(new GCMParameterSpec(96, nonce));
            Assertions.assertEquals(len, ok.getParameterSpec(GCMParameterSpec.class).getIV().length);
        }
        for (int len : new int[]{6, 14})
        {
            byte[] nonce = new byte[len];
            random.nextBytes(nonce);
            AlgorithmParameters bad = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
            Assertions.assertThrows(java.security.spec.InvalidParameterSpecException.class,
                    () -> bad.init(new GCMParameterSpec(96, nonce)),
                    len + "-byte CCM nonce must be rejected at spec init");
        }

        // Decode side at the same boundaries: 6-byte nonce rejected, 7 accepted,
        // 13 accepted, 14 rejected.
        Assertions.assertThrows(java.io.IOException.class,
                () -> decodeCcm(derCcm(6)), "6-byte nonce DER must be rejected");
        Assertions.assertEquals(7, decodeCcm(derCcm(7)).getIV().length);
        Assertions.assertEquals(13, decodeCcm(derCcm(13)).getIV().length);
        Assertions.assertThrows(java.io.IOException.class,
                () -> decodeCcm(derCcm(14)), "14-byte nonce DER must be rejected");

        // ICV negatives at spec init: 40 bits (icv 5) and 24 bits (icv 3) are
        // byte-aligned but not in the RFC 5084 set.
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        for (int badBits : new int[]{24, 40})
        {
            AlgorithmParameters bad = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
            Assertions.assertThrows(java.security.spec.InvalidParameterSpecException.class,
                    () -> bad.init(new GCMParameterSpec(badBits, nonce)),
                    badBits + "-bit CCM ICV must be rejected");
        }

        // Null spec / wrong-type spec. (A null NONCE can't be probed through
        // the public spec types — GCMParameterSpec and IvParameterSpec both
        // reject a null IV in their own constructors, so the codec's null-nonce
        // branch is defensive only.)
        AlgorithmParameters p2 = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(java.security.spec.InvalidParameterSpecException.class,
                () -> p2.init((java.security.spec.AlgorithmParameterSpec) null));
        AlgorithmParameters p3 = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(java.security.spec.InvalidParameterSpecException.class,
                () -> p3.init(new javax.crypto.spec.PBEParameterSpec(new byte[8], 1)));
    }

    /** Build SEQUENCE { OCTET STRING nonce(len) } with the default (omitted) ICV. */
    private static byte[] derCcm(int nonceLen)
    {
        byte[] out = new byte[4 + nonceLen];
        out[0] = 0x30;
        out[1] = (byte) (2 + nonceLen);
        out[2] = 0x04;
        out[3] = (byte) nonceLen;
        for (int i = 0; i < nonceLen; i++)
        {
            out[4 + i] = (byte) i;
        }
        return out;
    }

    private static GCMParameterSpec decodeCcm(byte[] der) throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        params.init(der);
        return params.getParameterSpec(GCMParameterSpec.class);
    }

    /**
     * BER-permissive decode pin: an encoding that carries the explicit-DEFAULT
     * {@code INTEGER 12} (which strict DER omits, but a foreign encoder may
     * emit) is accepted and reads back as ICV 12. Locks the tolerant-decode /
     * strict-encode posture so a future "tighten the decoder" change is
     * deliberate.
     */
    @Test
    public void ccmAlgorithmParameters_acceptsExplicitDefaultIcv() throws Exception
    {
        byte[] octetString = {0x04, 0x0c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
        byte[] explicitDefault = concat(concat(new byte[]{0x30, 0x11}, octetString), new byte[]{0x02, 0x01, 0x0c});

        GCMParameterSpec spec = decodeCcm(explicitDefault);
        Assertions.assertEquals(96, spec.getTLen(), "explicit-DEFAULT ICV 12 must decode to 96 bits");

        // ...and re-encoding produces the canonical (DEFAULT-omitted) DER form.
        AlgorithmParameters params = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        params.init(explicitDefault);
        byte[] reEncoded = params.getEncoded();
        byte[] canonical = concat(new byte[]{0x30, 0x0e}, octetString);
        Assertions.assertArrayEquals(canonical, reEncoded,
                "re-encode of an explicit-DEFAULT input must produce the canonical omitted form");
    }

    /** IvParameterSpec extraction + uninitialised-state guards on the CCM params. */
    @Test
    public void ccmAlgorithmParameters_ivSpecAndGuards() throws Exception
    {
        SecureRandom random = seededRandom("ccmAlgorithmParameters_ivSpecAndGuards");
        byte[] nonce = new byte[13];
        random.nextBytes(nonce);

        AlgorithmParameters params = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        params.init(new GCMParameterSpec(128, nonce));
        Assertions.assertArrayEquals(nonce, params.getParameterSpec(IvParameterSpec.class).getIV(),
                "IvParameterSpec extraction must return the nonce");

        AlgorithmParameters fresh = AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);
        Assertions.assertThrows(java.security.spec.InvalidParameterSpecException.class,
                () -> fresh.getParameterSpec(GCMParameterSpec.class),
                "getParameterSpec before init must throw InvalidParameterSpecException");
        Assertions.assertThrows(java.io.IOException.class, fresh::getEncoded,
                "getEncoded before init must throw IOException");
    }

    /**
     * Cipher integration for the newly-wired {@code CCMCipherSpi.engineGetParameters}:
     * the returned parameters must carry the ACTUAL session nonce + ICV (not
     * defaults) and drive the decrypt — mirroring the GCM/OCB round-trip tests.
     */
    @Test
    public void ccmCipherExposesParameters() throws Exception
    {
        SecureRandom random = seededRandom("ccmCipherExposesParameters");
        SecretKey key = aes256Key(random);
        byte[] nonce = new byte[7 + random.nextInt(7)];
        random.nextBytes(nonce);
        byte[] msg = new byte[37];
        random.nextBytes(msg);

        Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(64, nonce));
        AlgorithmParameters params = enc.getParameters();
        Assertions.assertNotNull(params, "CCM cipher must expose AlgorithmParameters after init");
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertArrayEquals(nonce, spec.getIV(), "exposed params must carry the session nonce");
        Assertions.assertEquals(64, spec.getTLen(), "exposed params must carry the session ICV");

        byte[] ct = enc.doFinal(msg);
        Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        dec.init(Cipher.DECRYPT_MODE, key, params);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct),
                "CCM round-trip via getParameters() failed");
    }

    /**
     * An AEAD-shaped spec (BC's {@code AEADParameterSpec}) on a NON-AEAD mode
     * must be rejected — silently falling into the IvParameterSpec branch would
     * drop its tag length and AAD, the exact failure mode the reflective
     * accessor exists to prevent. BC rejects this combination too.
     */
    @Test
    public void aeadSpecRejectedOnNonAeadMode() throws Exception
    {
        SecureRandom random = seededRandom("aeadSpecRejectedOnNonAeadMode");
        SecretKey key = aes256Key(random);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        byte[] aad = new byte[8];
        random.nextBytes(aad);

        Cipher cbc = Cipher.getInstance(CBC, JostleProvider.PROVIDER_NAME);
        try
        {
            cbc.init(Cipher.ENCRYPT_MODE, key,
                    new org.bouncycastle.jcajce.spec.AEADParameterSpec(iv, 128, aad), random);
            Assertions.fail("AEADParameterSpec on AES/CBC must be rejected");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            Assertions.assertTrue(
                    expected.getMessage().startsWith("AEAD parameter spec cannot be used with non-AEAD mode"),
                    "unexpected message: " + expected.getMessage());
        }
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
