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
import org.openssl.jostle.jcajce.spec.KMACParameterSpec;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Message authentication codes. A receiver verifies a tag by computing it again and comparing with
 * `MessageDigest.isEqual`, which takes the same time whatever the bytes are.
 */
public class MacExamplesTest
        extends JslExamples
{
    /**
     * HMAC-SHA256 over a message. Key and message are RFC 4231 test case 1, so the tag is known.
     */
    @Test
    public void hmacSha256()
            throws Exception
    {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        Mac mac = Mac.getInstance("HmacSHA256", "JSL");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] tag = mac.doFinal("Hi There".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                Hex.toHexString(tag));
    }

    /**
     * Every HMAC JSL registers: the receiver recomputes the tag and accepts it, and a changed message gives a
     * different tag.
     */
    @Test
    public void everyHmac()
            throws Exception
    {
        String[] names = {"HmacSHA1", "HmacSHA224", "HmacSHA384", "HmacSHA512", "HmacSHA512/224",
                "HmacSHA512/256", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512", "HmacMD5",
                "HmacMD5SHA1", "HmacRIPEMD160", "HmacSM3"};
        byte[] key = "a 32-byte key for the HMAC demo!".getBytes(StandardCharsets.US_ASCII);
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            Mac sender = Mac.getInstance(name, "JSL");
            sender.init(new SecretKeySpec(key, name));
            byte[] tag = sender.doFinal(msg);
            Mac receiver = Mac.getInstance(name, "JSL");
            receiver.init(new SecretKeySpec(key, name));
            Assertions.assertTrue(MessageDigest.isEqual(tag, receiver.doFinal(msg)), name);
            Assertions.assertFalse(MessageDigest.isEqual(tag, receiver.doFinal("attack at dusk".getBytes(
                    StandardCharsets.US_ASCII))), name);
        }
    }

    /**
     * AES-CMAC takes an AES key of 16, 24 or 32 bytes and produces a 16-byte tag.
     */
    @Test
    public void aesCmac()
            throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"), "AES");
        Mac mac = Mac.getInstance("AESCMAC", "JSL");
        mac.init(key);
        byte[] tag = mac.doFinal(Hex.decode("6bc1bee22e409f96e93d7e117393172a"));
        // NIST SP 800-38B example 2
        Assertions.assertEquals("070a16b46b4d4144f79bdd9dd04a287c", Hex.toHexString(tag));
    }

    /**
     * AES-GMAC needs a nonce as well as the key. Use a fresh 12-byte nonce for every message under a key:
     * after one tag the instance refuses more input until it is initialised again.
     */
    @Test
    public void aesGmac()
            throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        byte[] nonce = Hex.decode("000102030405060708090a0b");
        byte[] msg = "authenticated, not encrypted".getBytes(StandardCharsets.US_ASCII);
        Mac sender = Mac.getInstance("AESGMAC", "JSL");
        sender.init(key, new IvParameterSpec(nonce));
        byte[] tag = sender.doFinal(msg);
        Mac receiver = Mac.getInstance("AESGMAC", "JSL");
        receiver.init(key, new IvParameterSpec(nonce));
        Assertions.assertTrue(MessageDigest.isEqual(tag, receiver.doFinal(msg)));
        Assertions.assertEquals(16, tag.length);
    }

    /**
     * Poly1305 is a one-time authenticator: its 32-byte key must never be used for a second message.
     */
    @Test
    public void poly1305()
            throws Exception
    {
        byte[] key = Hex.decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        Mac mac = Mac.getInstance("POLY1305", "JSL");
        mac.init(new SecretKeySpec(key, "POLY1305"));
        byte[] tag = mac.doFinal("Cryptographic Forum Research Group".getBytes(StandardCharsets.US_ASCII));
        // RFC 8439 section 2.5.2
        Assertions.assertEquals("a8061dc1305136c6c22b8baf0c0127a9", Hex.toHexString(tag));
    }

    /**
     * KMAC takes an optional customisation string and output length through `KMACParameterSpec`; the same
     * key and message under a different customisation string give a different tag.
     */
    @Test
    public void kmacWithCustomisation()
            throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(new byte[32], "KMAC");
        byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
        for (String name : new String[]{"KMAC128", "KMAC256"})
        {
            Mac a = Mac.getInstance(name, "JSL");
            a.init(key, new KMACParameterSpec(256, "app one".getBytes(StandardCharsets.US_ASCII)));
            byte[] tagA = a.doFinal(msg);
            Mac b = Mac.getInstance(name, "JSL");
            b.init(key, new KMACParameterSpec(256, "app two".getBytes(StandardCharsets.US_ASCII)));
            Assertions.assertEquals(32, tagA.length, name);
            Assertions.assertFalse(MessageDigest.isEqual(tagA, b.doFinal(msg)), name);
        }
    }
}
