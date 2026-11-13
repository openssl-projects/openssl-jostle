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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ChaCha20CounterParameterSpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The ChaCha20CounterParameterSpec contract on every Java version: the spec's own refusals and copies, the RFC 8439
 * vectors at their initial counters, getIV and getParameters, the IvParameterSpec refusals and the RFC 8439
 * per-nonce limit of 2^32 blocks.
 *
 * <p>Expected key streams near the limit come from {@link #reference}, written from RFC 8439 2.3 and checked here
 * against the RFC vectors: Java 8 has no SunJCE ChaCha20, and BouncyCastle's engine stops one block before the
 * limit. ChaCha20AgreementTest holds the agreement against BouncyCastle.
 */
public class ChaCha20CounterParameterSpecTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
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
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        R.nextBytes(b);
        return b;
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce, int counter) throws Exception
    {
        Cipher c = Cipher.getInstance("ChaCha20", JSL);
        c.init(mode, new SecretKeySpec(key, "ChaCha20"), new ChaCha20CounterParameterSpec(nonce, counter));
        return c;
    }

    private static int rotl(int v, int n)
    {
        return (v << n) | (v >>> (32 - n));
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d)
    {
        x[a] += x[b];
        x[d] = rotl(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = rotl(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = rotl(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = rotl(x[b] ^ x[c], 7);
    }

    private static int le32(byte[] b, int off)
    {
        return (b[off] & 0xFF) | (b[off + 1] & 0xFF) << 8 | (b[off + 2] & 0xFF) << 16 | (b[off + 3] & 0xFF) << 24;
    }

    /** RFC 8439 2.3 and 2.4: msg XOR the key stream from block counter c, the counter not passing 2^32 - 1. */
    private static byte[] reference(byte[] key, byte[] nonce, int counter, byte[] msg)
    {
        byte[] out = new byte[msg.length];
        int block = counter;
        for (int off = 0; off < msg.length; off += 64)
        {
            int[] s = new int[16];
            s[0] = 0x61707865;
            s[1] = 0x3320646e;
            s[2] = 0x79622d32;
            s[3] = 0x6b206574;
            for (int i = 0; i < 8; i++)
            {
                s[4 + i] = le32(key, 4 * i);
            }
            s[12] = block;
            for (int i = 0; i < 3; i++)
            {
                s[13 + i] = le32(nonce, 4 * i);
            }
            int[] x = s.clone();
            for (int r = 0; r < 10; r++)
            {
                quarterRound(x, 0, 4, 8, 12);
                quarterRound(x, 1, 5, 9, 13);
                quarterRound(x, 2, 6, 10, 14);
                quarterRound(x, 3, 7, 11, 15);
                quarterRound(x, 0, 5, 10, 15);
                quarterRound(x, 1, 6, 11, 12);
                quarterRound(x, 2, 7, 8, 13);
                quarterRound(x, 3, 4, 9, 14);
            }
            for (int i = 0; i < 64 && off + i < msg.length; i++)
            {
                int w = x[i / 4] + s[i / 4];
                out[off + i] = (byte) (msg[off + i] ^ (w >>> (8 * (i % 4))));
            }
            block++;
        }
        return out;
    }

    /** As BouncyCastle's and the JDK's specs: a null nonce and a nonce of any length but 12 are refused. */
    @Test
    public void spec_refusesANullOrWrongLengthNonce()
    {
        NullPointerException npe = assertThrows(NullPointerException.class,
            () -> new ChaCha20CounterParameterSpec(null, 0));
        Assertions.assertEquals("nonce cannot be null", npe.getMessage());
        for (int len : new int[]{0, 11, 13, 16})
        {
            IllegalArgumentException iae = assertThrows(IllegalArgumentException.class,
                () -> new ChaCha20CounterParameterSpec(new byte[len], 0), "length " + len);
            Assertions.assertEquals("nonce must be 12 bytes long", iae.getMessage());
        }
    }

    /** The nonce is copied in and out, and the counter is carried as given, a negative int included. */
    @Test
    public void spec_copiesTheNonceAndCarriesTheCounter()
    {
        byte[] nonce = randomBytes(12);
        byte[] original = Arrays.clone(nonce);
        ChaCha20CounterParameterSpec spec = new ChaCha20CounterParameterSpec(nonce, -1);
        nonce[0] ^= 1;
        Assertions.assertArrayEquals(original, spec.getNonce());
        spec.getNonce()[0] ^= 1;
        Assertions.assertArrayEquals(original, spec.getNonce());
        Assertions.assertEquals(-1, spec.getCounter());
    }

    /**
     * The RFC 8439 vectors at their stated initial counters through the spec, both directions; the reference agrees
     * with every vector; and a counter one higher yields a different ciphertext.
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
            byte[] key = Hex.decode(vectors[i][0]);
            byte[] nonce = Hex.decode(vectors[i][1]);
            byte[] pt = Hex.decode(vectors[i][2]);
            byte[] ct = Hex.decode(vectors[i][3]);
            String label = "vector " + i + " counter " + counters[i];

            Assertions.assertArrayEquals(ct, reference(key, nonce, counters[i], pt), label + " reference");
            Assertions.assertArrayEquals(ct, cipher(Cipher.ENCRYPT_MODE, key, nonce, counters[i]).doFinal(pt),
                label + " encrypt");
            Assertions.assertArrayEquals(pt, cipher(Cipher.DECRYPT_MODE, key, nonce, counters[i]).doFinal(ct),
                label + " decrypt");
            Assertions.assertFalse(Arrays.areEqual(ct,
                cipher(Cipher.ENCRYPT_MODE, key, nonce, counters[i] + 1).doFinal(pt)), label + " counter + 1");
        }
    }

    /** At counter 0 the spec gives the same key stream as an IvParameterSpec carrying the nonce. */
    @Test
    public void counterZero_matchesIvParameterSpec() throws Exception
    {
        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(12);
        byte[] msg = randomBytes(80);
        Cipher viaIv = Cipher.getInstance("ChaCha20", JSL);
        viaIv.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(viaIv.doFinal(msg), cipher(Cipher.ENCRYPT_MODE, key, nonce, 0).doFinal(msg));
    }

    /** As the JDK: getIV reports the nonce and getParameters is null at a non-zero counter. */
    @Test
    public void nonZeroCounter_reportsTheNonceAndNoParameters() throws Exception
    {
        byte[] nonce = randomBytes(12);
        Cipher c = cipher(Cipher.ENCRYPT_MODE, randomBytes(32), nonce, 1 + R.nextInt(Integer.MAX_VALUE - 1));
        Assertions.assertArrayEquals(nonce, c.getIV());
        Assertions.assertNull(c.getParameters());
    }

    /** The counter enters only through the spec: an IvParameterSpec of 16 bytes stays refused. */
    @Test
    public void ivParameterSpecOfSixteenBytes_isRefused() throws Exception
    {
        for (int len : new int[]{11, 13, 16})
        {
            Cipher c = Cipher.getInstance("ChaCha20", JSL);
            InvalidAlgorithmParameterException ex = assertThrows(InvalidAlgorithmParameterException.class,
                () -> c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(randomBytes(32), "ChaCha20"),
                    new IvParameterSpec(new byte[len])));
            Assertions.assertEquals("invalid iv length", ex.getMessage(), "length " + len);
        }
    }

    /** RFC 8439 per-nonce limit: block 2^32 - 1 is served, whole, both directions, and equals the reference. */
    @Test
    public void rfc8439PerNonceLimit_theLastBlockIsServed() throws Exception
    {
        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(12);
        for (int[] cell : new int[][]{{0xFFFFFFFF, 64}, {0xFFFFFFFE, 128}})
        {
            byte[] msg = randomBytes(cell[1]);
            byte[] expected = reference(key, nonce, cell[0], msg);
            String label = String.format("counter 0x%08x length %d", cell[0], cell[1]);
            Cipher enc = cipher(Cipher.ENCRYPT_MODE, key, nonce, cell[0]);
            Assertions.assertArrayEquals(expected, enc.doFinal(msg), label + " encrypt");
            Cipher dec = cipher(Cipher.DECRYPT_MODE, key, nonce, cell[0]);
            Assertions.assertArrayEquals(msg, dec.doFinal(expected), label + " decrypt");
        }
    }

    /** RFC 8439 per-nonce limit: a request that would pass block 2^32 - 1 is refused whole, both directions. */
    @Test
    public void rfc8439PerNonceLimit_aCrossingRequestIsRefused() throws Exception
    {
        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(12);
        for (int[] cell : new int[][]{{0xFFFFFFFF, 65}, {0xFFFFFFFF, 128}, {0xFFFFFFFE, 129}})
        {
            for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
            {
                Cipher c = cipher(mode, key, nonce, cell[0]);
                IllegalStateException ex = assertThrows(IllegalStateException.class,
                    () -> c.doFinal(new byte[cell[1]]),
                    String.format("counter 0x%08x length %d mode %d", cell[0], cell[1], mode));
                Assertions.assertEquals(LIMIT_MESSAGE, ex.getMessage());
            }
        }
    }

    /**
     * RFC 8439 per-nonce limit, chunked: 64 bytes at counter 2^32 - 1 equal the reference,
     * and the next byte is refused by the call that crosses.
     */
    @Test
    public void rfc8439PerNonceLimit_chunkedCrossingIsRefusedAtTheCallThatCrosses() throws Exception
    {
        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(12);
        byte[] msg = randomBytes(65);
        byte[] expected = reference(key, nonce, 0xFFFFFFFF, Arrays.copyOfRange(msg, 0, 64));

        Cipher c = cipher(Cipher.ENCRYPT_MODE, key, nonce, 0xFFFFFFFF);
        Assertions.assertArrayEquals(expected, c.update(msg, 0, 64));
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> c.update(msg, 64, 1));
        Assertions.assertEquals(LIMIT_MESSAGE, ex.getMessage());
    }

    /** RFC 8439 per-nonce limit: doFinal and a re-init both return the stream to its initial counter. */
    @Test
    public void rfc8439PerNonceLimit_resetAndReinitClearThePosition() throws Exception
    {
        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(12);
        byte[] msg = randomBytes(64);
        byte[] expected = reference(key, nonce, 0xFFFFFFFF, msg);

        Cipher c = cipher(Cipher.DECRYPT_MODE, key, nonce, 0xFFFFFFFF);
        Assertions.assertArrayEquals(expected, c.doFinal(msg), "first");
        Assertions.assertArrayEquals(expected, c.doFinal(msg), "after doFinal");

        c.update(msg);
        assertThrows(IllegalStateException.class, () -> c.update(new byte[1]));
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20CounterParameterSpec(nonce, -1));
        Assertions.assertArrayEquals(expected, c.doFinal(msg), "after a refusal and re-init");

        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20CounterParameterSpec(nonce, 0));
        byte[] zeros = new byte[200];
        Assertions.assertArrayEquals(reference(key, nonce, 0, zeros), c.doFinal(zeros), "re-init to counter 0");
    }

    /**
     * BouncyCastle's engine refuses the same crossing with the same type, measured live. It stops one block
     * earlier than RFC 8439, so the shared cell is 129 bytes from block 2^32 - 2.
     */
    @Test
    public void rfc8439PerNonceLimit_refusalTypeMatchesBouncyCastle() throws Exception
    {
        byte[] key = randomBytes(32);
        byte[] nonce = randomBytes(12);

        ChaCha7539Engine engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        engine.seekTo(0xFFFFFFFEL * 64);
        assertThrows(IllegalStateException.class,
            () -> engine.processBytes(new byte[129], 0, 129, new byte[129], 0));

        Cipher c = cipher(Cipher.ENCRYPT_MODE, key, nonce, 0xFFFFFFFE);
        assertThrows(IllegalStateException.class, () -> c.doFinal(new byte[129]));
    }
}
