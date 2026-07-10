/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES through the FIPS provider ("JSLFIPS"): CBC/GCM/CCM/CTR/ECB and
 * key-wrap agree with the non-FIPS provider and BouncyCastle in the same
 * JVM, AEAD tampering is rejected, and unapproved ciphers are absent. Gated
 * on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSAESTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int[] KEY_SIZES = {16, 24, 32};

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static SecretKey randomKey(int size)
    {
        byte[] keyBytes = new byte[size];
        RANDOM.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Test
    public void cbcAgreesAcrossProviders()
        throws Exception
    {
        ensureProviders();

        for (int keySize : KEY_SIZES)
        {
            for (int t = 0; t < 5; t++)
            {
                SecretKey key = randomKey(keySize);
                byte[] iv = new byte[16];
                RANDOM.nextBytes(iv);
                byte[] message = new byte[1 + RANDOM.nextInt(1024)];
                RANDOM.nextBytes(message);

                Cipher fips = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleFIPSProvider.PROVIDER_NAME);
                fips.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                byte[] ct = fips.doFinal(message);

                Assertions.assertFalse(java.util.Arrays.equals(message,
                                java.util.Arrays.copyOf(ct, message.length)),
                        "ciphertext must differ from plaintext");

                Cipher bc = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
                bc.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                Assertions.assertArrayEquals(message, bc.doFinal(ct), "JSLFIPS encrypt -> BC decrypt");

                Cipher jsl = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleProvider.PROVIDER_NAME);
                jsl.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                Assertions.assertArrayEquals(ct, jsl.doFinal(message), "JSLFIPS vs JSL ciphertext");

                bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                byte[] bcCt = bc.doFinal(message);
                Cipher fipsDec = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleFIPSProvider.PROVIDER_NAME);
                fipsDec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                Assertions.assertArrayEquals(message, fipsDec.doFinal(bcCt), "BC encrypt -> JSLFIPS decrypt");
            }
        }
    }

    @Test
    public void gcmAgreesAndAuthenticates()
        throws Exception
    {
        ensureProviders();

        for (int keySize : KEY_SIZES)
        {
            SecretKey key = randomKey(keySize);
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            byte[] aad = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(aad);
            byte[] message = new byte[1 + RANDOM.nextInt(1024)];
            RANDOM.nextBytes(message);
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

            Cipher fips = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
            fips.init(Cipher.ENCRYPT_MODE, key, spec);
            fips.updateAAD(aad);
            byte[] ct = fips.doFinal(message);

            Cipher bc = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            bc.init(Cipher.ENCRYPT_MODE, key, spec);
            bc.updateAAD(aad);
            Assertions.assertArrayEquals(ct, bc.doFinal(message), "JSLFIPS vs BC GCM ciphertext+tag");

            Cipher fipsDec = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
            fipsDec.init(Cipher.DECRYPT_MODE, key, spec);
            fipsDec.updateAAD(aad);
            Assertions.assertArrayEquals(message, fipsDec.doFinal(ct), "GCM round trip");

            // Tamper the tag: authentication must fail.
            byte[] tampered = ct.clone();
            tampered[tampered.length - 1] ^= 0x01;
            Cipher fipsBad = Cipher.getInstance("AES/GCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
            fipsBad.init(Cipher.DECRYPT_MODE, key, spec);
            fipsBad.updateAAD(aad);
            Assertions.assertThrows(AEADBadTagException.class, () -> fipsBad.doFinal(tampered),
                    "tampered GCM tag must be rejected");
        }
    }

    @Test
    public void ccmAgreesWithBouncyCastle()
        throws Exception
    {
        ensureProviders();

        SecretKey key = randomKey(32);
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] message = new byte[1 + RANDOM.nextInt(512)];
        RANDOM.nextBytes(message);
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        Cipher fips = Cipher.getInstance("AES/CCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        fips.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ct = fips.doFinal(message);

        Cipher bc = Cipher.getInstance("AES/CCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(Cipher.ENCRYPT_MODE, key, spec);
        Assertions.assertArrayEquals(ct, bc.doFinal(message), "JSLFIPS vs BC CCM");

        Cipher fipsDec = Cipher.getInstance("AES/CCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        fipsDec.init(Cipher.DECRYPT_MODE, key, spec);
        Assertions.assertArrayEquals(message, fipsDec.doFinal(ct), "CCM round trip");

        byte[] tampered = ct.clone();
        tampered[RANDOM.nextInt(tampered.length)] ^= 0x01;
        Cipher fipsBad = Cipher.getInstance("AES/CCM/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        fipsBad.init(Cipher.DECRYPT_MODE, key, spec);
        Assertions.assertThrows(Exception.class, () -> fipsBad.doFinal(tampered),
                "tampered CCM must be rejected");
    }

    @Test
    public void ctrAndEcbAgreeViaBarePrimary()
        throws Exception
    {
        ensureProviders();

        SecretKey key = randomKey(32);
        byte[] message = new byte[1 + RANDOM.nextInt(1024)];
        RANDOM.nextBytes(message);

        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        Cipher fipsCtr = Cipher.getInstance("AES/CTR/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        fipsCtr.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        Cipher jslCtr = Cipher.getInstance("AES/CTR/NoPadding", JostleProvider.PROVIDER_NAME);
        jslCtr.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        Assertions.assertArrayEquals(jslCtr.doFinal(message), fipsCtr.doFinal(message), "CTR agreement");

        Cipher fipsEcb = Cipher.getInstance("AES/ECB/PKCS5Padding", JostleFIPSProvider.PROVIDER_NAME);
        fipsEcb.init(Cipher.ENCRYPT_MODE, key);
        Cipher jslEcb = Cipher.getInstance("AES/ECB/PKCS5Padding", JostleProvider.PROVIDER_NAME);
        jslEcb.init(Cipher.ENCRYPT_MODE, key);
        Assertions.assertArrayEquals(jslEcb.doFinal(message), fipsEcb.doFinal(message), "ECB agreement");
    }

    @Test
    public void keyWrapAgreesWithBouncyCastle()
        throws Exception
    {
        ensureProviders();

        SecretKey kek = randomKey(32);
        SecretKey target = randomKey(16);

        // RFC 3394 key wrap, registered by OID (as in the non-FIPS provider).
        String wrapOid = "2.16.840.1.101.3.4.1.45"; // id-aes256-wrap
        Cipher fipsWrap = Cipher.getInstance(wrapOid, JostleFIPSProvider.PROVIDER_NAME);
        fipsWrap.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = fipsWrap.wrap(target);

        Cipher bcUnwrap = Cipher.getInstance("AESWrap", BouncyCastleProvider.PROVIDER_NAME);
        bcUnwrap.init(Cipher.UNWRAP_MODE, kek);
        Key recovered = bcUnwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(target.getEncoded(), recovered.getEncoded(),
                "JSLFIPS wrap -> BC unwrap");

        Cipher bcWrap = Cipher.getInstance("AESWrap", BouncyCastleProvider.PROVIDER_NAME);
        bcWrap.init(Cipher.WRAP_MODE, kek);
        byte[] bcWrapped = bcWrap.wrap(target);
        Cipher fipsUnwrap = Cipher.getInstance(wrapOid, JostleFIPSProvider.PROVIDER_NAME);
        fipsUnwrap.init(Cipher.UNWRAP_MODE, kek);
        Key recovered2 = fipsUnwrap.unwrap(bcWrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(target.getEncoded(), recovered2.getEncoded(),
                "BC wrap -> JSLFIPS unwrap");
    }

    @Test
    public void unapprovedCiphersRejected()
        throws Exception
    {
        ensureProviders();

        for (String name : new String[]{"ChaCha20", "CAMELLIA", "ARIA", "SM4", "DESede"})
        {
            Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> Cipher.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " must not resolve through JSLFIPS");
        }

        // ... while the non-FIPS provider still serves them in the same JVM.
        Assertions.assertNotNull(Cipher.getInstance("ChaCha20", JostleProvider.PROVIDER_NAME));
    }

    /**
     * A cipher initialised with a key whose algorithm is not AES must fail
     * with InvalidKeyException (the JCE type that drives provider fallback),
     * carrying the exact "unsupported key algorithm ARIA" message — not a
     * ProviderException, ClassCastException, or bare IllegalArgumentException.
     * Mirrors AESAgreementTest.testRejectIncorrectKeyAlgorithm through the
     * FIPS registration.
     */
    @Test
    public void wrongKeyAlgorithmRejectedWithInvalidKeyException()
        throws Exception
    {
        ensureProviders();

        SecretKeySpec wrongSpec = new SecretKeySpec(new byte[16], "ARIA");

        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec);
            Assertions.fail("Should have thrown an exception");
        }
        catch (InvalidKeyException ikes)
        {
            Assertions.assertEquals("unsupported key algorithm ARIA", ikes.getMessage());
        }

        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, wrongSpec, new IvParameterSpec(new byte[16]));
            Assertions.fail("Should have thrown an exception");
        }
        catch (InvalidKeyException ikes)
        {
            Assertions.assertEquals("unsupported key algorithm ARIA", ikes.getMessage());
        }

        // Correct spec initialises without throwing.
        Cipher ok = Cipher.getInstance("AES/ECB/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        ok.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));

        ok = Cipher.getInstance("AES/CBC/NoPadding", JostleFIPSProvider.PROVIDER_NAME);
        ok.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]));
    }

    /**
     * AES/CCM through JSLFIPS must accept a plain IvParameterSpec (nonce
     * only) and, because the spec carries no tag length, default to a
     * 64-bit (8-byte) tag — matching BouncyCastle's CCM IV-only default —
     * so the ciphertext+tag agrees with BC byte-for-byte. Mirrors
     * AESAgreementTest.aesCCM_ivParameterSpec_agreesWithBC.
     */
    @Test
    public void ccmIvParameterSpecAgreesWithBc()
        throws Exception
    {
        ensureProviders();

        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        RANDOM.nextBytes(key);
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        byte[] aad = new byte[RANDOM.nextInt(48)];
        RANDOM.nextBytes(aad);
        byte[] msg = new byte[1 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(msg);

        SecretKey secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec spec = new IvParameterSpec(iv);

        Cipher bcEnc = Cipher.getInstance(xform, BouncyCastleProvider.PROVIDER_NAME);
        bcEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        bcEnc.updateAAD(aad);
        byte[] bcCt = bcEnc.doFinal(msg);

        Cipher joEnc = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        joEnc.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        joEnc.updateAAD(aad);
        byte[] joCt = joEnc.doFinal(msg);

        Assertions.assertArrayEquals(bcCt, joCt,
                "AES-CCM IvParameterSpec diverged from BC (default tag length mismatch?)");
        // 64-bit default tag => ciphertext is plaintext + 8 bytes.
        Assertions.assertEquals(msg.length + 8, joCt.length, "expected 8-byte default CCM tag");

        // Decrypt must also accept IvParameterSpec.
        Cipher joDec = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        joDec.init(Cipher.DECRYPT_MODE, secretKey, spec);
        joDec.updateAAD(aad);
        Assertions.assertArrayEquals(msg, joDec.doFinal(joCt), "AES-CCM IvParameterSpec roundtrip failed");
    }

    /**
     * AES/CCM through JSLFIPS enforces its mode/parameter contracts:
     * WRAP_MODE and UNWRAP_MODE are rejected with
     * IllegalStateException("invalid operation mode"); a wrong-length AES
     * key is rejected with InvalidKeyException; a tag length outside the
     * RFC-5084 set (multiple of 8 but out of range, or a non-multiple of 8)
     * is rejected with InvalidAlgorithmParameterException. Mirrors
     * AESAgreementTest.aesCCM_wrapMode_rejected / _wrongKeyLength_rejected /
     * _tagLength_boundaryRejection.
     */
    @Test
    public void ccmModeAndParamRejections()
        throws Exception
    {
        ensureProviders();

        String xform = "AES/CCM/NoPadding";
        byte[] key = new byte[16];
        RANDOM.nextBytes(key);
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        // WRAP_MODE / UNWRAP_MODE are not supported by CCM.
        for (int opMode : new int[]{Cipher.WRAP_MODE, Cipher.UNWRAP_MODE})
        {
            Cipher c = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
            try
            {
                c.init(opMode, secretKey, new GCMParameterSpec(128, iv));
                Assertions.fail("CCM must reject opMode " + opMode);
            }
            catch (IllegalStateException expected)
            {
                Assertions.assertEquals("invalid operation mode", expected.getMessage());
            }
        }

        // A 20-byte key is not a valid AES key length.
        Cipher badKeyCipher = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        try
        {
            badKeyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[20], "AES"),
                    new GCMParameterSpec(128, iv));
            Assertions.fail("CCM must reject a 20-byte AES key");
        }
        catch (InvalidKeyException expected)
        {
            // expected
        }

        // Tag lengths outside {32,48,64,80,96,112,128} (bits) are rejected:
        // 24 below the minimum, 40 an odd-byte gap, 136 above the maximum,
        // and 33 a non-multiple of 8.
        for (int badTagBits : new int[]{24, 40, 136, 33})
        {
            Cipher c = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
            try
            {
                c.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(badTagBits, iv));
                Assertions.fail("AES-CCM must reject tag length " + badTagBits + " bits");
            }
            catch (InvalidAlgorithmParameterException expected)
            {
                // expected
            }
        }
    }

    /**
     * One JSLFIPS AES/CBC instance re-used across operations: two distinct
     * messages both round-trip correctly, and after a decrypt driven to a
     * padding failure the same instance re-inits and decrypts cleanly —
     * proving the reset/reInit path is not poisoned by a prior failure.
     * Mirrors AESAgreementTest.aesCCM_resetReuse_acrossOperations (CBC
     * analogue).
     */
    @Test
    public void cbcResetReuseAcrossOperations()
        throws Exception
    {
        ensureProviders();

        String xform = "AES/CBC/PKCS5Padding";
        SecretKey key = randomKey(32);
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        IvParameterSpec spec = new IvParameterSpec(iv);

        // Two distinct encrypt operations on one instance.
        Cipher enc = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        byte[] m1 = new byte[1 + RANDOM.nextInt(200)];
        RANDOM.nextBytes(m1);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] c1 = enc.doFinal(m1);

        Cipher dec1 = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        dec1.init(Cipher.DECRYPT_MODE, key, spec);
        Assertions.assertArrayEquals(m1, dec1.doFinal(c1), "first CBC round-trip");

        byte[] m2 = new byte[1 + RANDOM.nextInt(200)];
        RANDOM.nextBytes(m2);
        enc.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] c2 = enc.doFinal(m2);

        Cipher dec2 = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        dec2.init(Cipher.DECRYPT_MODE, key, spec);
        Assertions.assertArrayEquals(m2, dec2.doFinal(c2), "second CBC round-trip on reused encrypt instance");

        // Negative-then-positive on a single decrypt instance: a tampered
        // final block corrupts the PKCS#5 padding.
        Cipher dec = Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME);
        byte[] tampered = c2.clone();
        tampered[tampered.length - 1] ^= (byte) 0xFF;
        dec.init(Cipher.DECRYPT_MODE, key, spec);
        try
        {
            byte[] out = dec.doFinal(tampered);
            // Padding may coincidentally validate; if so, the plaintext must
            // still not equal the original message.
            Assertions.assertFalse(org.openssl.jostle.util.Arrays.areEqual(m2, out),
                    "tampered ciphertext that didn't throw still must not round-trip");
        }
        catch (BadPaddingException expected)
        {
            // expected
        }
        // Same instance must still work for a clean decrypt afterwards.
        dec.init(Cipher.DECRYPT_MODE, key, spec);
        Assertions.assertArrayEquals(m2, dec.doFinal(c2),
                "instance poisoned after a padding-induced failure");
    }

    /**
     * Positive complement to unapprovedCiphersRejected: every registered AES
     * OID transformation (id-aes{128,192,256}-{CBC,GCM,wrap,wrap_pad}) and
     * the bare AES128/AES192/AES256 primaries must resolve through JSLFIPS.
     * A registration drift that dropped an approved OID would surface here as
     * a NoSuchAlgorithmException from getInstance.
     */
    @Test
    public void approvedOidSurfaceResolves()
        throws Exception
    {
        ensureProviders();

        String[] oids =
                {
                        NISTObjectIdentifiers.id_aes128_CBC.getId(),
                        NISTObjectIdentifiers.id_aes128_GCM.getId(),
                        NISTObjectIdentifiers.id_aes128_wrap.getId(),
                        NISTObjectIdentifiers.id_aes128_wrap_pad.getId(),
                        NISTObjectIdentifiers.id_aes192_CBC.getId(),
                        NISTObjectIdentifiers.id_aes192_GCM.getId(),
                        NISTObjectIdentifiers.id_aes192_wrap.getId(),
                        NISTObjectIdentifiers.id_aes192_wrap_pad.getId(),
                        NISTObjectIdentifiers.id_aes256_CBC.getId(),
                        NISTObjectIdentifiers.id_aes256_GCM.getId(),
                        NISTObjectIdentifiers.id_aes256_wrap.getId(),
                        NISTObjectIdentifiers.id_aes256_wrap_pad.getId(),
                        "AES128",
                        "AES192",
                        "AES256"
                };

        for (String name : oids)
        {
            Assertions.assertNotNull(Cipher.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " must resolve through JSLFIPS");
        }
    }
}
