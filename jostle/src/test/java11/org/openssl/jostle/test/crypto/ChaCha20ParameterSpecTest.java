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

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exercises the Java-11+ {@code ChaCha20BlockCipherSpi} override (loaded from
 * {@code META-INF/versions/11}) that accepts {@code javax.crypto.spec.ChaCha20ParameterSpec}.
 *
 * <p>Lives in {@code src/test/java11} so it compiles at {@code release = 11}
 * (where the spec exists) and runs under {@code unitTest11} on JDK 11 — i.e. the
 * multi-release override is verified on its actual target JDK, not only on 25.
 *
 * <p>The initial block counter is the unsigned 32-bit state word of RFC 8439 2.3; ChaCha20CounterAgreementTest
 * holds the agreement against SunJCE and BouncyCastle. RFC 8439 2.4 allows 2^32 blocks per nonce, so
 * a request that would take the counter past 2^32 is refused whole with IllegalStateException, the type
 * BouncyCastle's ChaCha7539Engine raises at that limit.
 */
public class ChaCha20ParameterSpecTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String SUN = "SunJCE";
    private static final String LIMIT_MESSAGE = "ChaCha20 block counter would pass 2^32 for this nonce";
    private static final SecureRandom R = new SecureRandom();

    // RFC 8439 2.4.2
    private static final String RFC8439_2_4_2_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private static final String RFC8439_2_4_2_NONCE = "000000000000004a00000000";
    private static final String RFC8439_2_4_2_PT =
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
        + "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        + "637265656e20776f756c642062652069742e";
    private static final String RFC8439_2_4_2_CT =
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
        + "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        + "5af90bbf74a35be6b40b8eedf2785e42874d";
    private static final int RFC8439_2_4_2_COUNTER = 1;
    // RFC 8439 A.2-1
    private static final String RFC8439_A_2_1_KEY = "0000000000000000000000000000000000000000000000000000000000000000";
    private static final String RFC8439_A_2_1_NONCE = "000000000000000000000000";
    private static final String RFC8439_A_2_1_PT =
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        + "00000000000000000000000000000000";
    private static final String RFC8439_A_2_1_CT =
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a37"
        + "6a43b8f41518a11cc387b669b2ee6586";
    private static final int RFC8439_A_2_1_COUNTER = 0;
    // RFC 8439 A.2-2
    private static final String RFC8439_A_2_2_KEY = "0000000000000000000000000000000000000000000000000000000000000001";
    private static final String RFC8439_A_2_2_NONCE = "000000000000000000000002";
    private static final String RFC8439_A_2_2_PT =
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472"
        + "696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
        + "20496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d616465207769"
        + "7468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572"
        + "656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c75"
        + "6465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
        + "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e"
        + "792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f";
    private static final String RFC8439_A_2_2_CT =
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d37005"
        + "0e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
        + "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66"
        + "424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
        + "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84"
        + "a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
        + "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd85"
        + "14ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221";
    private static final int RFC8439_A_2_2_COUNTER = 1;
    // RFC 8439 A.2-3
    private static final String RFC8439_A_2_3_KEY = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
    private static final String RFC8439_A_2_3_NONCE = "000000000000000000000002";
    private static final String RFC8439_A_2_3_PT =
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e64"
        + "2067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
        + "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e";
    private static final String RFC8439_A_2_3_CT =
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871"
        + "fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
        + "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1";
    private static final int RFC8439_A_2_3_COUNTER = 42;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecretKey randomKey()
    {
        return randomKey(R);
    }

    private static SecretKey randomKey(SecureRandom sr)
    {
        byte[] key = new byte[32];
        sr.nextBytes(key);
        return new SecretKeySpec(key, "ChaCha20");
    }

    private static byte[] randomNonce(SecureRandom sr)
    {
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        return nonce;
    }

    private static Cipher cipher(String provider, int mode, SecretKey key, byte[] nonce, int counter)
        throws Exception
    {
        Cipher c = Cipher.getInstance("ChaCha20", provider);
        c.init(mode, key, new ChaCha20ParameterSpec(nonce, counter));
        return c;
    }

    /**
     * ChaCha20ParameterSpec(nonce, counter=0) is accepted and produces the same
     * keystream as the equivalent IvParameterSpec(nonce) — confirming the
     * counter-0 convention the native layer assumes.
     */
    @Test
    public void chaChaParameterSpec_counter0_matchesIvParameterSpec() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = new byte[12];
        R.nextBytes(nonce);
        byte[] msg = new byte[80];
        R.nextBytes(msg);

        Cipher viaSpec = Cipher.getInstance("ChaCha20", JSL);
        viaSpec.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        byte[] ctSpec = viaSpec.doFinal(msg);

        Cipher viaIv = Cipher.getInstance("ChaCha20", JSL);
        viaIv.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] ctIv = viaIv.doFinal(msg);

        Assertions.assertArrayEquals(ctIv, ctSpec, "ChaCha20ParameterSpec(counter 0) == IvParameterSpec");

        // Round-trip via the spec.
        Cipher dec = Cipher.getInstance("ChaCha20", JSL);
        dec.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        Assertions.assertArrayEquals(msg, dec.doFinal(ctSpec));
    }

    /**
     * The RFC 8439 vectors at their stated initial counters, both directions, and a counter one higher yields a
     * different ciphertext, so the counter is not ignored.
     */
    @Test
    public void rfc8439Vectors_atTheirInitialCounters() throws Exception
    {
        String[][] vectors = {
            {RFC8439_2_4_2_KEY, RFC8439_2_4_2_NONCE, RFC8439_2_4_2_PT, RFC8439_2_4_2_CT},
            {RFC8439_A_2_1_KEY, RFC8439_A_2_1_NONCE, RFC8439_A_2_1_PT, RFC8439_A_2_1_CT},
            {RFC8439_A_2_2_KEY, RFC8439_A_2_2_NONCE, RFC8439_A_2_2_PT, RFC8439_A_2_2_CT},
            {RFC8439_A_2_3_KEY, RFC8439_A_2_3_NONCE, RFC8439_A_2_3_PT, RFC8439_A_2_3_CT}};
        int[] counters = {RFC8439_2_4_2_COUNTER, RFC8439_A_2_1_COUNTER, RFC8439_A_2_2_COUNTER,
            RFC8439_A_2_3_COUNTER};
        for (int i = 0; i < vectors.length; i++)
        {
            SecretKey key = new SecretKeySpec(Hex.decode(vectors[i][0]), "ChaCha20");
            byte[] nonce = Hex.decode(vectors[i][1]);
            byte[] pt = Hex.decode(vectors[i][2]);
            byte[] ct = Hex.decode(vectors[i][3]);
            String label = "vector " + i + " counter " + counters[i];

            Assertions.assertArrayEquals(ct,
                cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counters[i]).doFinal(pt), label + " encrypt");
            Assertions.assertArrayEquals(pt,
                cipher(JSL, Cipher.DECRYPT_MODE, key, nonce, counters[i]).doFinal(ct), label + " decrypt");
            Assertions.assertFalse(Arrays.areEqual(ct,
                cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counters[i] + 1).doFinal(pt)), label + " counter + 1");
        }
    }

    /** As the JDK: getIV reports the nonce and getParameters is null at a non-zero counter. */
    @Test
    public void nonZeroCounter_reportsTheNonceAndNoParameters() throws Exception
    {
        byte[] nonce = randomNonce(R);
        int counter = 1 + R.nextInt(Integer.MAX_VALUE - 1);
        Cipher jsl = cipher(JSL, Cipher.ENCRYPT_MODE, randomKey(), nonce, counter);
        Cipher sun = cipher(SUN, Cipher.ENCRYPT_MODE, randomKey(), nonce, counter);
        Assertions.assertArrayEquals(nonce, jsl.getIV());
        Assertions.assertArrayEquals(sun.getIV(), jsl.getIV());
        Assertions.assertNull(sun.getParameters());
        Assertions.assertNull(jsl.getParameters());
    }

    /** The counter enters only through ChaCha20ParameterSpec: a 16-byte IvParameterSpec stays refused. */
    @Test
    public void ivParameterSpecOfSixteenBytes_isRefused() throws Exception
    {
        for (int len : new int[]{11, 13, 16})
        {
            Cipher c = Cipher.getInstance("ChaCha20", JSL);
            InvalidAlgorithmParameterException ex = assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, randomKey(), new IvParameterSpec(new byte[len])));
            Assertions.assertEquals("invalid iv length", ex.getMessage(), "length " + len);
        }
    }

    /** RFC 8439 per-nonce limit: block 2^32 - 1 is served, whole, and equals SunJCE. */
    @Test
    public void rfc8439PerNonceLimit_theLastBlockIsServed() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = randomNonce(R);
        for (int[] cell : new int[][]{{0xFFFFFFFF, 64}, {0xFFFFFFFE, 128}})
        {
            byte[] msg = new byte[cell[1]];
            R.nextBytes(msg);
            for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
            {
                Assertions.assertArrayEquals(cipher(SUN, mode, key, nonce, cell[0]).doFinal(msg),
                    cipher(JSL, mode, key, nonce, cell[0]).doFinal(msg),
                    String.format("counter 0x%08x length %d mode %d", cell[0], cell[1], mode));
            }
        }
    }

    /** RFC 8439 per-nonce limit: a request that would pass block 2^32 - 1 is refused whole, both directions. */
    @Test
    public void rfc8439PerNonceLimit_aCrossingRequestIsRefused() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = randomNonce(R);
        for (int[] cell : new int[][]{{0xFFFFFFFF, 65}, {0xFFFFFFFF, 128}, {0xFFFFFFFE, 129}})
        {
            for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
            {
                Cipher c = cipher(JSL, mode, key, nonce, cell[0]);
                IllegalStateException ex = assertThrows(IllegalStateException.class,
                    () -> c.doFinal(new byte[cell[1]]),
                    String.format("counter 0x%08x length %d mode %d", cell[0], cell[1], mode));
                Assertions.assertEquals(LIMIT_MESSAGE, ex.getMessage());
            }
        }
    }

    /**
     * RFC 8439 per-nonce limit, chunked: 64 bytes at counter 2^32 - 1 equal SunJCE,
     * and the next byte is refused by the call that crosses.
     */
    @Test
    public void rfc8439PerNonceLimit_chunkedCrossingIsRefusedAtTheCallThatCrosses() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = randomNonce(R);
        byte[] msg = new byte[65];
        R.nextBytes(msg);
        byte[] sun = cipher(SUN, Cipher.ENCRYPT_MODE, key, nonce, 0xFFFFFFFF).doFinal(msg, 0, 64);

        Cipher jsl = cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, 0xFFFFFFFF);
        Assertions.assertArrayEquals(sun, jsl.update(msg, 0, 64));
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jsl.update(msg, 64, 1));
        Assertions.assertEquals(LIMIT_MESSAGE, ex.getMessage());
    }

    /** RFC 8439 per-nonce limit: doFinal and a re-init both return the stream to its initial counter. */
    @Test
    public void rfc8439PerNonceLimit_resetAndReinitClearThePosition() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = randomNonce(R);
        byte[] msg = new byte[64];
        R.nextBytes(msg);
        byte[] expected = cipher(SUN, Cipher.DECRYPT_MODE, key, nonce, 0xFFFFFFFF).doFinal(msg);

        Cipher jsl = cipher(JSL, Cipher.DECRYPT_MODE, key, nonce, 0xFFFFFFFF);
        Assertions.assertArrayEquals(expected, jsl.doFinal(msg), "first");
        Assertions.assertArrayEquals(expected, jsl.doFinal(msg), "after doFinal");

        jsl.update(msg);
        assertThrows(IllegalStateException.class, () -> jsl.update(new byte[1]));
        jsl.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0xFFFFFFFF));
        Assertions.assertArrayEquals(expected, jsl.doFinal(msg), "after a refusal and re-init");

        jsl.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        Assertions.assertArrayEquals(cipher(SUN, Cipher.DECRYPT_MODE, key, nonce, 0).doFinal(new byte[200]),
            jsl.doFinal(new byte[200]), "re-init to counter 0");
    }

    /**
     * BouncyCastle's engine refuses the same crossing with the same type, measured live. It stops one block
     * earlier than RFC 8439 and SunJCE, so the shared cell is 129 bytes from block 2^32 - 2.
     */
    @Test
    public void rfc8439PerNonceLimit_refusalTypeMatchesBouncyCastle() throws Exception
    {
        byte[] keyBytes = new byte[32];
        R.nextBytes(keyBytes);
        byte[] nonce = randomNonce(R);

        ChaCha7539Engine engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(keyBytes), nonce));
        engine.seekTo(0xFFFFFFFEL * 64);
        assertThrows(IllegalStateException.class,
            () -> engine.processBytes(new byte[129], 0, 129, new byte[129], 0));

        Cipher jsl = cipher(JSL, Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "ChaCha20"), nonce, 0xFFFFFFFE);
        assertThrows(IllegalStateException.class, () -> jsl.doFinal(new byte[129]));
    }
}
