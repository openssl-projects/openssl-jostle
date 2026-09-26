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
import org.openssl.jostle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Message digests. Jostle registers OpenSSL's names (`SHA2-256`) and the JDK's (`SHA-256`) resolves to the
 * same service.
 */
public class MessageDigestExamplesTest
        extends JslExamples
{
    /**
     * Hash a message with SHA-256, one shot. The expected value is the FIPS 180-2 vector for "abc".
     */
    @Test
    public void sha256OneShot()
            throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256", "JSL");
        byte[] hash = md.digest("abc".getBytes(StandardCharsets.US_ASCII));
        Assertions.assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Hex.toHexString(hash));
    }

    /**
     * Hash a message fed in pieces; the result equals the one-shot hash. SHA3-256 of "abc" is the FIPS 202
     * vector.
     */
    @Test
    public void sha3IncrementalUpdates()
            throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA3-256", "JSL");
        md.update((byte) 'a');
        md.update("bc".getBytes(StandardCharsets.US_ASCII), 0, 2);
        byte[] hash = md.digest();
        Assertions.assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                Hex.toHexString(hash));
    }

    /**
     * SHAKE is an extendable-output function. Through MessageDigest it produces its default length: 32 bytes
     * for SHAKE-128 and 64 for SHAKE-256, and the named variants fix the length in the name.
     */
    @Test
    public void shakeDefaultOutputLengths()
            throws Exception
    {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        Assertions.assertEquals(32, MessageDigest.getInstance("SHAKE-128", "JSL").digest(msg).length);
        Assertions.assertEquals(64, MessageDigest.getInstance("SHAKE-256", "JSL").digest(msg).length);
        Assertions.assertEquals(32, MessageDigest.getInstance("SHAKE128-256", "JSL").digest(msg).length);
        Assertions.assertEquals(64, MessageDigest.getInstance("SHAKE256-512", "JSL").digest(msg).length);
    }

    /**
     * Every other digest JSL registers, driven the same way: the length the digest reports is the length it
     * produces, and a one-bit change in the input changes the output.
     */
    @Test
    public void everyOtherDigest()
            throws Exception
    {
        String[] names = {"SHA1", "SHA2-224", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
                "SHA3-224", "SHA3-384", "SHA3-512", "MD5", "MD5-SHA1", "RIPEMD-160", "SM3", "BLAKE2B-512",
                "BLAKE2S-256"};
        byte[] a = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] b = "abd".getBytes(StandardCharsets.US_ASCII);
        for (String name : names)
        {
            MessageDigest md = MessageDigest.getInstance(name, "JSL");
            byte[] ha = md.digest(a);
            Assertions.assertEquals(md.getDigestLength(), ha.length, name);
            Assertions.assertFalse(MessageDigest.isEqual(ha, md.digest(b)), name);
        }
    }
}
