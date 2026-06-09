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

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
