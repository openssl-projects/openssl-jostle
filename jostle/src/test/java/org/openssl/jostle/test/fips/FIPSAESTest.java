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

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES through the FIPS provider ("JSLFIPS"): CBC/GCM/CCM/CTR/ECB and
 * key-wrap agree with the non-FIPS provider and BouncyCastle in the same
 * JVM, AEAD tampering is rejected, and unapproved ciphers are absent. Gated
 * on JOSTLE_TEST_FIPS_DIR; skipped when unset.
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
}
