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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

/**
 * Ciphers: symmetric encryption, key wrapping, and public-key encryption and key transport. Generate a fresh
 * key and a fresh IV or nonce for every message; the fixed IVs below only keep the examples short.
 */
public class CipherExamplesTest
        extends JslExamples
{
    /**
     * AES-GCM with additional authenticated data. The ciphertext carries the 16-byte tag at its end, and any
     * change to it, or to the AAD, fails decryption with `AEADBadTagException`.
     */
    @Test
    public void aesGcmEncryptAndDecrypt()
            throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "JSL");
        kg.init(256);
        SecretKey key = kg.generateKey();
        byte[] nonce = Hex.decode("cafebabefacedbaddecaf888");
        byte[] aad = "header".getBytes(StandardCharsets.US_ASCII);
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        enc.updateAAD(aad);
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        dec.updateAAD(aad);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));

        ct[0] ^= 1;
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        dec.updateAAD(aad);
        Assertions.assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct));
    }

    /**
     * AES-CCM is its own transformation. With a plain `IvParameterSpec` its tag is 64 bits (GCM's is 128);
     * pass a `GCMParameterSpec` to choose the tag length. The same holds for ARIA and SM4.
     */
    @Test
    public void ccmEncryptAndDecrypt()
            throws Exception
    {
        String[] names = {"AES/CCM/NoPadding", "ARIA/CCM/NoPadding", "SM4/CCM/NoPadding"};
        String[] keyAlgs = {"AES", "ARIA", "SM4"};
        byte[] nonce = Hex.decode("00112233445566778899aabb");
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            SecretKeySpec key = new SecretKeySpec(new byte[16], keyAlgs[i]);
            Cipher enc = Cipher.getInstance(names[i], "JSL");
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            byte[] ct = enc.doFinal(msg);
            Assertions.assertEquals(msg.length + 8, ct.length, names[i]);
            Cipher dec = Cipher.getInstance(names[i], "JSL");
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(64, nonce));
            Assertions.assertArrayEquals(msg, dec.doFinal(ct), names[i]);
        }
    }

    /**
     * CBC with PKCS#5 padding over each block cipher, with a key of any size the cipher supports. The IV is
     * one block: 16 bytes, or 8 for DESede.
     */
    @Test
    public void cbcOverEveryBlockCipher()
            throws Exception
    {
        String[] names = {"AES", "ARIA", "CAMELLIA", "SM4", "DESEDE"};
        int[] keyBytes = {32, 32, 32, 16, 24};
        byte[] msg = "twenty-five bytes of text".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            Cipher enc = Cipher.getInstance(names[i] + "/CBC/PKCS5Padding", "JSL");
            SecretKeySpec key = new SecretKeySpec(new byte[keyBytes[i]], names[i]);
            IvParameterSpec iv = new IvParameterSpec(new byte[enc.getBlockSize()]);
            enc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ct = enc.doFinal(msg);
            Cipher dec = Cipher.getInstance(names[i] + "/CBC/PKCS5Padding", "JSL");
            dec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct), names[i]);
        }
    }

    /**
     * The names with a size in them (`AES128`, `ARIA256`, ...) are the ECB entries of the NIST, KISA and
     * NTT object identifiers: ECB only, and only with a key of that size. For any other mode use the bare
     * name. ECB leaks patterns in the plaintext; do not use it for data.
     */
    @Test
    public void sizePinnedEcbNames()
            throws Exception
    {
        String[] names = {"AES128", "AES192", "AES256", "ARIA128", "ARIA192", "ARIA256", "CAMELLIA128",
                "CAMELLIA192", "CAMELLIA256"};
        int[] keyBytes = {16, 24, 32, 16, 24, 32, 16, 24, 32};
        byte[] block = "sixteen byte blk".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            SecretKeySpec key = new SecretKeySpec(new byte[keyBytes[i]], names[i]);
            Cipher enc = Cipher.getInstance(names[i] + "/ECB/NoPadding", "JSL");
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = enc.doFinal(block);
            Cipher dec = Cipher.getInstance(names[i] + "/ECB/NoPadding", "JSL");
            dec.init(Cipher.DECRYPT_MODE, key);
            Assertions.assertArrayEquals(block, dec.doFinal(ct), names[i]);
        }
    }

    /**
     * Ciphertext stealing: CBC without padding for any input of at least one block, the ciphertext the same
     * length as the plaintext. `AES/CBC/CS3Padding` and `AES/CTS/NoPadding` are the same construction.
     */
    @Test
    public void aesCiphertextStealing()
            throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        byte[] msg = "twenty-five bytes of text".getBytes(StandardCharsets.US_ASCII);
        for (String name : new String[]{"AES/CBC/CS3Padding", "AES/CTS/NoPadding"})
        {
            Cipher enc = Cipher.getInstance(name, "JSL");
            enc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ct = enc.doFinal(msg);
            Assertions.assertEquals(msg.length, ct.length, name);
            Cipher dec = Cipher.getInstance(name, "JSL");
            dec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct), name);
        }
    }

    /**
     * AES-XTS for storage encryption: a double-length key (two different AES keys) and a 16-byte tweak,
     * usually the sector number. Each data unit is at least 16 bytes.
     */
    @Test
    public void aesXts()
            throws Exception
    {
        byte[] keyBytes = new byte[64];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte) i;
        }
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec tweak = new IvParameterSpec(Hex.decode("07000000000000000000000000000000"));
        byte[] sector = "a sector of forty bytes of disk content.".getBytes(StandardCharsets.US_ASCII);
        Cipher enc = Cipher.getInstance("AES/XTS/NoPadding", "JSL");
        enc.init(Cipher.ENCRYPT_MODE, key, tweak);
        byte[] ct = enc.doFinal(sector);
        Cipher dec = Cipher.getInstance("AES/XTS/NoPadding", "JSL");
        dec.init(Cipher.DECRYPT_MODE, key, tweak);
        Assertions.assertArrayEquals(sector, dec.doFinal(ct));
    }

    /**
     * ChaCha20-Poly1305 (authenticated) and plain ChaCha20 (a stream cipher, no integrity), both with a
     * 32-byte key and a 12-byte nonce given as an `IvParameterSpec`.
     */
    @Test
    public void chaCha20()
            throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        IvParameterSpec nonce = new IvParameterSpec(Hex.decode("000000000000004a00000000"));
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : new String[]{"ChaCha20-Poly1305", "ChaCha20"})
        {
            Cipher enc = Cipher.getInstance(name, "JSL");
            enc.init(Cipher.ENCRYPT_MODE, key, nonce);
            byte[] ct = enc.doFinal(msg);
            Cipher dec = Cipher.getInstance(name, "JSL");
            dec.init(Cipher.DECRYPT_MODE, key, nonce);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct), name);
        }
    }

    /**
     * AES key wrap (RFC 3394) of a 16-byte key under a 16-byte key-encryption key; the result is the RFC's
     * own test vector. A tampered blob fails `unwrap` with `InvalidKeyException`.
     */
    @Test
    public void aesKeyWrap()
            throws Exception
    {
        SecretKeySpec kek = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        Cipher wrapper = Cipher.getInstance("AESWRAP", "JSL");
        wrapper.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = wrapper.wrap(cek);
        Assertions.assertEquals("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", Hex.toHexString(wrapped));

        Cipher unwrapper = Cipher.getInstance("AESWRAP", "JSL");
        unwrapper.init(Cipher.UNWRAP_MODE, kek);
        Key back = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded());
    }

    /**
     * The other wrap modes: `AESWRAPPAD` (RFC 5649) wraps a key of any length, `AESWRAPINV` is RFC 3394
     * with the inverse cipher, and the RFC 3211 wraps take an IV and add random padding, so each wrap of the
     * same key differs.
     */
    @Test
    public void otherKeyWraps()
            throws Exception
    {
        String[] names = {"AESWRAPPAD", "AESWRAPINV", "AESRFC3211WRAP", "CAMELLIARFC3211WRAP",
                "DESEDERFC3211WRAP"};
        int[] ivBytes = {0, 0, 16, 16, 8};
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        for (int i = 0; i < names.length; i++)
        {
            SecretKeySpec kek = new SecretKeySpec(new byte[24], names[i]);
            Cipher w = Cipher.getInstance(names[i], "JSL");
            Cipher u = Cipher.getInstance(names[i], "JSL");
            if (ivBytes[i] == 0)
            {
                w.init(Cipher.WRAP_MODE, kek);
                u.init(Cipher.UNWRAP_MODE, kek);
            }
            else
            {
                w.init(Cipher.WRAP_MODE, kek, new IvParameterSpec(new byte[ivBytes[i]]));
                u.init(Cipher.UNWRAP_MODE, kek, new IvParameterSpec(new byte[ivBytes[i]]));
            }
            Key back = u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY);
            Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(), names[i]);
        }
    }

    /**
     * RSA-OAEP. JSL's bare `RSA` cipher is OAEP with SHA-256 and MGF1-SHA-256, not PKCS#1 v1.5 and not
     * SHA-1, so give both sides an explicit `OAEPParameterSpec` when the peer is another provider.
     */
    @Test
    public void rsaOaep()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        byte[] msg = "a 32-byte session key goes here!".getBytes(StandardCharsets.US_ASCII);

        Cipher enc = Cipher.getInstance("RSA", "JSL");
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
        byte[] ct = enc.doFinal(msg);
        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", "JSL");
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    /**
     * RSA with PKCS#1 v1.5 padding, for interoperating with systems that still require it. Prefer OAEP for
     * anything new.
     */
    @Test
    public void rsaPkcs1()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        byte[] msg = "legacy key transport".getBytes(StandardCharsets.US_ASCII);
        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "JSL");
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] ct = enc.doFinal(msg);
        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "JSL");
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
    }

    /**
     * Key transport through a KEM: the `ML-KEM` and `RSA-KTS-KEM-KWS` ciphers encapsulate a secret to the
     * recipient's public key, derive a key-encryption key (KDF3 with SHA-256 by default) and AES-wrap the
     * key. `KTSParameterSpec` names the wrap and its key size, and both sides must use the same one.
     */
    @Test
    public void kemKeyTransport()
            throws Exception
    {
        String[] ciphers = {"ML-KEM", "RSA-KTS-KEM-KWS"};
        String[] keyPairs = {"ML-KEM-768", "RSA"};
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        KTSParameterSpec kts = new KTSParameterSpec.Builder("AESWRAP", 256).build();
        for (int i = 0; i < ciphers.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(keyPairs[i], "JSL").generateKeyPair();
            Cipher w = Cipher.getInstance(ciphers[i], "JSL");
            w.init(Cipher.WRAP_MODE, kp.getPublic(), kts);
            byte[] wrapped = w.wrap(cek);
            Cipher u = Cipher.getInstance(ciphers[i], "JSL");
            u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kts);
            Assertions.assertArrayEquals(cek.getEncoded(), u.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(),
                    ciphers[i]);
        }
    }

    /**
     * The ETSI EC key-encapsulation wrap (ETSI TS 102 941): wrap a key to an EC public key. The recipient
     * info in `IESKEMParameterSpec` is bound into the derivation, so both sides must pass the same bytes.
     */
    @Test
    public void etsiKemWrap()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair recipient = kpg.generateKeyPair();
        byte[] recipientInfo = "recipient id".getBytes(StandardCharsets.US_ASCII);
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");

        Cipher w = Cipher.getInstance("ETSIKEMwithSHA256", "JSL");
        w.init(Cipher.WRAP_MODE, recipient.getPublic(), new IESKEMParameterSpec(recipientInfo));
        byte[] wrapped = w.wrap(cek);
        Cipher u = Cipher.getInstance("ETSIKEMwithSHA256", "JSL");
        u.init(Cipher.UNWRAP_MODE, recipient.getPrivate(), new IESKEMParameterSpec(recipientInfo));
        Key back = u.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        Assertions.assertTrue(Arrays.equals(cek.getEncoded(), back.getEncoded()));
    }
}
