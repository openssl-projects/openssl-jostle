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

package org.openssl.jostle.test.rsa;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * RSA/ECB/PKCS1Padding on JSL beside BouncyCastle and SunJCE: interop in every direction, and one cell per measured
 * divergence holding every half. JSLFIPS registers no PKCS1 name, so this class has no FIPS twin.
 */
public class RSAPKCS1AgreementTest
{
    private static final String XFORM = "RSA/ECB/PKCS1Padding";
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String SUN_JCE = "SunJCE";
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A 2048-bit pair from the JDK's own generator, which every provider here accepts. */
    private static KeyPair keyPair;

    @BeforeAll
    static void before() throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();
    }

    private static Cipher cipher(String provider, int mode, Key key) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(mode, key);
        return c;
    }

    private static byte[] randomMessage(int len)
    {
        byte[] m = new byte[len];
        RANDOM.nextBytes(m);
        return m;
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @Test
    public void testPKCS1_BCEncrypt_JostleDecrypt() throws Exception
    {
        byte[] msg = randomMessage(64);
        byte[] ct = cipher(BC, Cipher.ENCRYPT_MODE, keyPair.getPublic()).doFinal(msg);
        Assertions.assertArrayEquals(msg, cipher(JSL, Cipher.DECRYPT_MODE, keyPair.getPrivate()).doFinal(ct));
    }

    @Test
    public void testPKCS1_JostleEncrypt_BCDecrypt() throws Exception
    {
        byte[] msg = randomMessage(64);
        byte[] ct = cipher(JSL, Cipher.ENCRYPT_MODE, keyPair.getPublic()).doFinal(msg);
        Assertions.assertArrayEquals(msg, cipher(BC, Cipher.DECRYPT_MODE, keyPair.getPrivate()).doFinal(ct));
    }

    /**
     * Multi-trial agreement with BouncyCastle: per-trial fresh keypair, random plaintext length and content, both
     * directions.
     */
    @Test
    public void testPKCS1_AgreementWithBC_MultiTrial() throws Exception
    {
        SecureRandom sr = seededRandom("testPKCS1_AgreementWithBC_MultiTrial");

        for (int trial = 0; trial < 10; trial++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            // PKCS#1 v1.5 max plaintext for a 2048-bit modulus = 256 - 11 = 245.
            int msgLen = sr.nextInt(246);
            byte[] msg = new byte[msgLen];
            sr.nextBytes(msg);

            byte[] ct = cipher(JSL, Cipher.ENCRYPT_MODE, kp.getPublic()).doFinal(msg);
            Assertions.assertArrayEquals(msg, cipher(BC, Cipher.DECRYPT_MODE, kp.getPrivate()).doFinal(ct),
                    "trial=" + trial + " msgLen=" + msgLen + ": BC failed to decrypt Jostle ct");

            byte[] ct2 = cipher(BC, Cipher.ENCRYPT_MODE, kp.getPublic()).doFinal(msg);
            Assertions.assertArrayEquals(msg, cipher(JSL, Cipher.DECRYPT_MODE, kp.getPrivate()).doFinal(ct2),
                    "trial=" + trial + " msgLen=" + msgLen + ": Jostle failed to decrypt BC ct");
        }
    }

    @Test
    public void testPKCS1_BCWrap_JostleUnwrap_AESKey() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey aesKey = kg.generateKey();

        byte[] wrapped = cipher(BC, Cipher.WRAP_MODE, keyPair.getPublic()).wrap(aesKey);
        Key unwrapped = cipher(JSL, Cipher.UNWRAP_MODE, keyPair.getPrivate()).unwrap(wrapped, "AES",
                Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
    }

    /** All six encrypt-here, decrypt-there pairs across JSL, SunJCE and BouncyCastle recover the message. */
    @Test
    public void everyCrossPairDecrypts() throws Exception
    {
        String[] providers = {JSL, SUN_JCE, BC};
        for (String encryptor : providers)
        {
            for (String decryptor : providers)
            {
                if (encryptor.equals(decryptor))
                {
                    continue;
                }
                byte[] msg = randomMessage(1 + RANDOM.nextInt(245));
                byte[] ct = cipher(encryptor, Cipher.ENCRYPT_MODE, keyPair.getPublic()).doFinal(msg);
                Assertions.assertArrayEquals(msg,
                        cipher(decryptor, Cipher.DECRYPT_MODE, keyPair.getPrivate()).doFinal(ct),
                        encryptor + " -> " + decryptor);
            }
        }
    }

    /**
     * k - 11 = 245 encrypts on all three; 246 through doFinal, through update then doFinal, and through 1 MiB of
     * update is refused. Ours and SunJCE: IllegalBlockSizeException naming the limit. BouncyCastle:
     * ArrayIndexOutOfBoundsException, outside the JCE contract, so the canonical type is ours.
     */
    @Test
    public void encryptBoundOneOverTheLimit() throws Exception
    {
        String limit = "Data must not be longer than 245 bytes";
        for (String p : new String[]{JSL, SUN_JCE, BC})
        {
            Assertions.assertEquals(256, cipher(p, Cipher.ENCRYPT_MODE, keyPair.getPublic())
                    .doFinal(randomMessage(245)).length, p);
        }
        for (String p : new String[]{JSL, SUN_JCE})
        {
            Cipher c = cipher(p, Cipher.ENCRYPT_MODE, keyPair.getPublic());
            Assertions.assertEquals(limit, Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> c.doFinal(randomMessage(246)), p).getMessage(), p);
            c.update(randomMessage(200));
            Assertions.assertEquals(limit, Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> c.doFinal(randomMessage(46)), p).getMessage(), p);
            c.update(new byte[1 << 20]);
            Assertions.assertEquals(limit, Assertions.assertThrows(IllegalBlockSizeException.class,
                    c::doFinal, p).getMessage(), p);
        }
        Cipher bc = cipher(BC, Cipher.ENCRYPT_MODE, keyPair.getPublic());
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bc.doFinal(randomMessage(246)));
    }

    /**
     * Decrypt input longer than k, 257 random bytes and a leading zero before 256, is a length refusal. Ours and
     * SunJCE: IllegalBlockSizeException naming k. BouncyCastle: ArrayIndexOutOfBoundsException.
     */
    @Test
    public void decryptInputLongerThanTheModulus() throws Exception
    {
        byte[] good = cipher(JSL, Cipher.ENCRYPT_MODE, keyPair.getPublic()).doFinal(randomMessage(19));
        byte[] leadingZero = new byte[257];
        System.arraycopy(good, 0, leadingZero, 1, 256);
        for (byte[] in : new byte[][]{randomMessage(257), leadingZero})
        {
            for (String p : new String[]{JSL, SUN_JCE})
            {
                Cipher c = cipher(p, Cipher.DECRYPT_MODE, keyPair.getPrivate());
                Assertions.assertEquals("Data must not be longer than 256 bytes",
                        Assertions.assertThrows(IllegalBlockSizeException.class, () -> c.doFinal(in), p)
                                .getMessage(), p);
            }
            Cipher bc = cipher(BC, Cipher.DECRYPT_MODE, keyPair.getPrivate());
            Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bc.doFinal(in));
        }
    }

    /**
     * 256 bytes whose value is at least n reach the library. Ours: BadPaddingException from the bare invalid
     * cipher text code. SunJCE: BadPaddingException. BouncyCastle: DataLengthException.
     */
    @Test
    public void decryptValueOverTheModulus() throws Exception
    {
        byte[] overN = new byte[256];
        Arrays.fill(overN, (byte) 0xFF);

        Cipher ours = cipher(JSL, Cipher.DECRYPT_MODE, keyPair.getPrivate());
        BadPaddingException e = Assertions.assertThrows(BadPaddingException.class, () -> ours.doFinal(overN));
        Assertions.assertTrue(e.getMessage().startsWith("invalid cipher text: "), e.getMessage());

        Cipher sun = cipher(SUN_JCE, Cipher.DECRYPT_MODE, keyPair.getPrivate());
        Assertions.assertEquals("Message is larger than modulus",
                Assertions.assertThrows(BadPaddingException.class, () -> sun.doFinal(overN)).getMessage());

        Cipher bc = cipher(BC, Cipher.DECRYPT_MODE, keyPair.getPrivate());
        Assertions.assertThrows(DataLengthException.class, () -> bc.doFinal(overN));
    }

    /**
     * Empty input reaches the library. Ours: BadPaddingException from the bare invalid cipher text code. SunJCE:
     * BadPaddingException. BouncyCastle: its BadBlockException.
     */
    @Test
    public void decryptEmptyInput() throws Exception
    {
        Cipher ours = cipher(JSL, Cipher.DECRYPT_MODE, keyPair.getPrivate());
        BadPaddingException e = Assertions.assertThrows(BadPaddingException.class, () -> ours.doFinal(new byte[0]));
        Assertions.assertEquals(BadPaddingException.class, e.getClass());
        Assertions.assertTrue(e.getMessage().startsWith("invalid cipher text: "), e.getMessage());

        Cipher sun = cipher(SUN_JCE, Cipher.DECRYPT_MODE, keyPair.getPrivate());
        Assertions.assertEquals("Padding error in decryption",
                Assertions.assertThrows(BadPaddingException.class, () -> sun.doFinal(new byte[0])).getMessage());

        Cipher bc = cipher(BC, Cipher.DECRYPT_MODE, keyPair.getPrivate());
        Assertions.assertEquals(BadBlockException.class,
                Assertions.assertThrows(BadPaddingException.class, () -> bc.doFinal(new byte[0])).getClass());
    }

    /**
     * A decision, not a type: ours refuses a private key to encrypt and a public key to decrypt at init. SunJCE
     * and BouncyCastle accept both at init and encrypt with the private key.
     */
    @Test
    public void keyDirectionIsRefusedHereAndAcceptedElsewhere() throws Exception
    {
        Cipher ours = Cipher.getInstance(XFORM, JSL);
        Assertions.assertEquals("encrypt/wrap requires an RSAPublicKey", Assertions.assertThrows(
                InvalidKeyException.class, () -> ours.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate())).getMessage());
        Assertions.assertEquals("decrypt/unwrap requires an RSAPrivateKey", Assertions.assertThrows(
                InvalidKeyException.class, () -> ours.init(Cipher.DECRYPT_MODE, keyPair.getPublic())).getMessage());

        for (String p : new String[]{SUN_JCE, BC})
        {
            Assertions.assertEquals(256, cipher(p, Cipher.ENCRYPT_MODE, keyPair.getPrivate())
                    .doFinal(randomMessage(19)).length, p);
            cipher(p, Cipher.DECRYPT_MODE, keyPair.getPublic());
        }
    }

    /**
     * Decrypt into a buffer exactly the plaintext's length: ours writes the 19 bytes; SunJCE and BouncyCastle ask
     * for a modulus-sized buffer and throw ShortBufferException.
     */
    @Test
    public void decryptIntoAnExactLengthBuffer() throws Exception
    {
        byte[] msg = randomMessage(19);
        byte[] ct = cipher(JSL, Cipher.ENCRYPT_MODE, keyPair.getPublic()).doFinal(msg);

        byte[] out = new byte[19];
        Assertions.assertEquals(19, cipher(JSL, Cipher.DECRYPT_MODE, keyPair.getPrivate())
                .doFinal(ct, 0, ct.length, out, 0));
        Assertions.assertArrayEquals(msg, out);

        for (String p : new String[]{SUN_JCE, BC})
        {
            Cipher c = cipher(p, Cipher.DECRYPT_MODE, keyPair.getPrivate());
            Assertions.assertThrows(ShortBufferException.class, () -> c.doFinal(ct, 0, ct.length, new byte[19], 0),
                    p);
        }
    }
}
