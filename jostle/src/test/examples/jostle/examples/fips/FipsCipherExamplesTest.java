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

package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;

/**
 * Ciphers in the FIPS module: AES in its modes and key wraps, Triple-DES for existing data, RSA-OAEP and key
 * transport. The 3.5.8 module serves no ARIA, Camellia, SM4 or ChaCha20, and JSLFIPS registers no RFC 3211 wrap
 * and no PKCS#1 v1.5 encryption. Generate a fresh key and a fresh IV or nonce for every message; the fixed IVs
 * below only keep the examples short.
 */
public class FipsCipherExamplesTest
        extends FipsExamples
{
    /**
     * AES-GCM with additional authenticated data; a changed ciphertext fails with `AEADBadTagException`.
     */
    @Test
    public void aesGcmEncryptAndDecrypt()
            throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "JSLFIPS");
        kg.init(256);
        SecretKey key = kg.generateKey();
        byte[] nonce = Hex.decode("cafebabefacedbaddecaf888");
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSLFIPS");
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        enc.updateAAD("header".getBytes(StandardCharsets.US_ASCII));
        byte[] ct = enc.doFinal(msg);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "JSLFIPS");
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        dec.updateAAD("header".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
        ct[0] ^= 1;
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        dec.updateAAD("header".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct));
    }

    /**
     * AES-CCM, CBC with padding, ciphertext stealing and XTS, each through one round trip. CCM with a plain
     * `IvParameterSpec` has a 64-bit tag; XTS takes a double-length key of two different AES keys.
     */
    @Test
    public void aesModes()
            throws Exception
    {
        String[] names = {"AES/CCM/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/CS3Padding", "AES/CTS/NoPadding",
                "AES/XTS/NoPadding"};
        int[] ivBytes = {12, 16, 16, 16, 16};
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        byte[] msg = "forty bytes of text for every AES mode.!".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            SecretKeySpec key = new SecretKeySpec(keyBytes, 0, names[i].contains("XTS") ? 64 : 32, "AES");
            IvParameterSpec iv = new IvParameterSpec(new byte[ivBytes[i]]);
            Cipher enc = Cipher.getInstance(names[i], "JSLFIPS");
            enc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ct = enc.doFinal(msg);
            Cipher dec = Cipher.getInstance(names[i], "JSLFIPS");
            dec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, dec.doFinal(ct), names[i]);
        }
    }

    /**
     * The size-pinned names (`AES128`, `AES192`, `AES256`) are the ECB entries of the NIST object identifiers:
     * ECB only, with a key of that size. ECB leaks patterns in the plaintext; do not use it for data.
     */
    @Test
    public void sizePinnedEcbNames()
            throws Exception
    {
        String[] names = {"AES128", "AES192", "AES256"};
        int[] keyBytes = {16, 24, 32};
        byte[] block = "sixteen byte blk".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < names.length; i++)
        {
            SecretKeySpec key = new SecretKeySpec(new byte[keyBytes[i]], "AES");
            Cipher enc = Cipher.getInstance(names[i] + "/ECB/NoPadding", "JSLFIPS");
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = enc.doFinal(block);
            Cipher dec = Cipher.getInstance(names[i] + "/ECB/NoPadding", "JSLFIPS");
            dec.init(Cipher.DECRYPT_MODE, key);
            Assertions.assertArrayEquals(block, dec.doFinal(ct), names[i]);
        }
    }

    /**
     * Triple-DES, for decrypting existing data: JSL encrypts and JSLFIPS decrypts. Whether the module also
     * encrypts depends on fipsinstall configuration; where it does not, as installed here, `init` for
     * encryption throws `InvalidKeyException` naming the restriction.
     */
    @Test
    public void tripleDesDecryptOnly()
            throws Exception
    {
        Assumptions.assumeTrue(Security.getProvider("JSLFIPS").getService("Cipher", "DESEDE") != null);
        SecretKeySpec key = new SecretKeySpec(Hex.decode("0123456789abcdeffedcba987654321089abcdef01234567"), "DESede");
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        Cipher legacy = Cipher.getInstance("DESede/CBC/PKCS5Padding", "JSL");
        legacy.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ct = legacy.doFinal("old data".getBytes(StandardCharsets.US_ASCII));

        Cipher dec = Cipher.getInstance("DESede/CBC/PKCS5Padding", "JSLFIPS");
        dec.init(Cipher.DECRYPT_MODE, key, iv);
        Assertions.assertArrayEquals("old data".getBytes(StandardCharsets.US_ASCII), dec.doFinal(ct));
        Cipher enc = Cipher.getInstance("DESede/CBC/PKCS5Padding", "JSLFIPS");
        try
        {
            enc.init(Cipher.ENCRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(ct, enc.doFinal("old data".getBytes(StandardCharsets.US_ASCII)));
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("Triple-DES encryption is not supported"), e.getMessage());
        }
    }

    /**
     * AES key wrap (RFC 3394) against the RFC's test vector, and the padded (RFC 5649) and inverse-cipher wraps.
     */
    @Test
    public void aesKeyWraps()
            throws Exception
    {
        SecretKeySpec kek = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        Cipher kw = Cipher.getInstance("AESWRAP", "JSLFIPS");
        kw.init(Cipher.WRAP_MODE, kek);
        Assertions.assertEquals("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", Hex.toHexString(kw.wrap(cek)));
        for (String name : new String[]{"AESWRAP", "AESWRAPPAD", "AESWRAPINV"})
        {
            Cipher w = Cipher.getInstance(name, "JSLFIPS");
            w.init(Cipher.WRAP_MODE, kek);
            Cipher u = Cipher.getInstance(name, "JSLFIPS");
            u.init(Cipher.UNWRAP_MODE, kek);
            Key back = u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY);
            Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(), name);
        }
    }

    /**
     * RSA-OAEP, the RSA encryption the module serves; the bare `RSA` name is OAEP with SHA-256. PKCS#1 v1.5
     * encryption is not available: asking for it fails with `NoSuchPaddingException`.
     */
    @Test
    public void rsaOaepAndNoPkcs1Encryption()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSLFIPS");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        byte[] msg = "a 32-byte session key goes here!".getBytes(StandardCharsets.US_ASCII);
        Cipher enc = Cipher.getInstance("RSA", "JSLFIPS");
        enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
        byte[] ct = enc.doFinal(msg);
        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", "JSLFIPS");
        dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct));
        Assertions.assertThrows(NoSuchPaddingException.class,
                () -> Cipher.getInstance("RSA/ECB/PKCS1Padding", "JSLFIPS"));
    }

    /**
     * Key transport through a KEM, `ML-KEM` and `RSA-KTS-KEM-KWS`, with `KTSParameterSpec` naming the wrap and
     * its size. ML-KEM runs where the module serves it.
     */
    @Test
    public void kemKeyTransport()
            throws Exception
    {
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        KTSParameterSpec kts = new KTSParameterSpec.Builder("AESWRAP", 256).build();
        String[] ciphers = {"ML-KEM", "RSA-KTS-KEM-KWS"};
        String[] keyPairs = {"ML-KEM-768", "RSA"};
        for (int i = 0; i < ciphers.length; i++)
        {
            if (Security.getProvider("JSLFIPS").getService("Cipher", ciphers[i]) == null)
            {
                continue;
            }
            KeyPair kp = KeyPairGenerator.getInstance(keyPairs[i], "JSLFIPS").generateKeyPair();
            Cipher w = Cipher.getInstance(ciphers[i], "JSLFIPS");
            w.init(Cipher.WRAP_MODE, kp.getPublic(), kts);
            Cipher u = Cipher.getInstance(ciphers[i], "JSLFIPS");
            u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kts);
            Assertions.assertArrayEquals(cek.getEncoded(), u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY)
                    .getEncoded(), ciphers[i]);
        }
    }

    /**
     * The ETSI EC key-encapsulation wrap: wrap a key to an EC public key, with recipient info bound into the
     * derivation.
     */
    @Test
    public void etsiKemWrap()
            throws Exception
    {
        SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "JSLFIPS");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair recipient = ec.generateKeyPair();
        Cipher w = Cipher.getInstance("ETSIKEMwithSHA256", "JSLFIPS");
        w.init(Cipher.WRAP_MODE, recipient.getPublic(), new IESKEMParameterSpec(new byte[]{1, 2, 3}));
        Cipher u = Cipher.getInstance("ETSIKEMwithSHA256", "JSLFIPS");
        u.init(Cipher.UNWRAP_MODE, recipient.getPrivate(), new IESKEMParameterSpec(new byte[]{1, 2, 3}));
        Assertions.assertArrayEquals(cek.getEncoded(), u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY).getEncoded());
    }
}
