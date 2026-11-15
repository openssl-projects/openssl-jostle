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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * RFC 3217 CMS Triple-DES key wrap (DESedeWrap, id-alg-CMS3DESwrap) against BouncyCastle 1.87. The wrap draws a
 * random IV, so outputs are compared by cross-unwrap, and byte for byte only in the RFC 3217 section 3.4 known
 * answer, where a fixed-bytes SecureRandom supplies the RFC's IV.
 */
public class DESedeWrapAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** Every spelling BouncyCastle 1.87 registers, all served by one SPI. */
    private static final String[] NAMES = {"DESedeWrap", "1.2.840.113549.1.9.16.3.6", "DESedeRFC3217Wrap", "TDEAWrap"};

    // RFC 3217 section 3.4.
    private static final byte[] CEK = Hex.decode("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
    private static final byte[] KEK = Hex.decode("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
    private static final byte[] IV = Hex.decode("5dd4cbfc96f5453b");
    private static final byte[] RESULT = Hex.decode(
            "690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4");

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int TRIALS = 5;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** A SecureRandom that returns the given bytes in order, and counts what it served. */
    static final class FixedBytes extends SecureRandom
    {
        private final byte[] bytes;
        int calls;
        int served;

        FixedBytes(byte[] bytes)
        {
            this.bytes = Arrays.clone(bytes);
        }

        @Override
        public void nextBytes(byte[] out)
        {
            calls++;
            for (int i = 0; i < out.length; i++)
            {
                out[i] = bytes[served++ % bytes.length];
            }
        }
    }

    /** A SecureRandom that counts the bytes it serves. */
    static final class Counting extends SecureRandom
    {
        int served;

        @Override
        public void nextBytes(byte[] out)
        {
            super.nextBytes(out);
            served += out.length;
        }
    }

    private static SecretKey key(byte[] k)
    {
        return new SecretKeySpec(k, "DESede");
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] wrap(String provider, String name, byte[] kek, byte[] cek) throws Exception
    {
        Cipher c = Cipher.getInstance(name, provider);
        c.init(Cipher.ENCRYPT_MODE, key(kek));
        return c.doFinal(cek);
    }

    private static byte[] unwrap(String provider, String name, byte[] kek, byte[] wrapped) throws Exception
    {
        Cipher c = Cipher.getInstance(name, provider);
        c.init(Cipher.DECRYPT_MODE, key(kek));
        return c.doFinal(wrapped);
    }

    /** RFC 3217 section 3.4, byte for byte, under every name: the IV comes from the caller's SecureRandom. */
    @Test
    public void rfc3217KnownAnswer() throws Exception
    {
        for (String name : NAMES)
        {
            FixedBytes iv = new FixedBytes(IV);
            Cipher c = Cipher.getInstance(name, JSL);
            c.init(Cipher.ENCRYPT_MODE, key(KEK), iv);
            Assertions.assertArrayEquals(RESULT, c.doFinal(CEK), name);
            Assertions.assertEquals(1, iv.calls, name + ": one draw for the IV");
            Assertions.assertEquals(8, iv.served, name + ": the IV is 8 bytes");

            FixedBytes none = new FixedBytes(IV);
            Cipher d = Cipher.getInstance(name, JSL);
            d.init(Cipher.DECRYPT_MODE, key(KEK), none);
            Assertions.assertArrayEquals(CEK, d.doFinal(RESULT), name);
            Assertions.assertEquals(0, none.served, name + ": unwrap draws no random bytes");

            byte[] changed = Arrays.clone(IV);
            changed[0] ^= 1;
            Cipher e = Cipher.getInstance(name, JSL);
            e.init(Cipher.ENCRYPT_MODE, key(KEK), new FixedBytes(changed));
            Assertions.assertFalse(Arrays.areEqual(RESULT, e.doFinal(CEK)), name + ": the IV changes the result");
        }
    }

    /** Ours unwraps BouncyCastle's wrap and BouncyCastle unwraps ours, for random keys of several lengths. */
    @Test
    public void crossUnwrapsWithBouncyCastle() throws Exception
    {
        int checked = 0;
        for (String name : NAMES)
        {
            for (int len : new int[]{8, 16, 24, 32, 64})
            {
                for (int t = 0; t < TRIALS; t++)
                {
                    byte[] kek = random(24);
                    byte[] cek = random(len);
                    String label = name + " len " + len;
                    byte[] ours = wrap(JSL, name, kek, cek);
                    Assertions.assertEquals(len + 16, ours.length, label);
                    Assertions.assertFalse(Arrays.areEqual(cek, Arrays.copyOfRange(ours, 8, 8 + len)), label);
                    Assertions.assertArrayEquals(cek, unwrap(BC, name, kek, ours), label + ": BC unwraps ours");
                    Assertions.assertArrayEquals(cek, unwrap(JSL, name, kek, wrap(BC, name, kek, cek)),
                            label + ": ours unwraps BC's");
                    byte[] otherKek = random(24);
                    assertThrows(BadPaddingException.class, () -> unwrap(JSL, name, otherKek, ours),
                            label + ": a wrong KEK fails the checksum");
                    checked++;
                }
            }
        }
        Assertions.assertEquals(4 * 5 * TRIALS, checked);
    }

    /** Cipher.wrap and Cipher.unwrap of a key cross with BouncyCastle in both directions. */
    @Test
    public void wrapAndUnwrapModesCrossWithBouncyCastle() throws Exception
    {
        for (String name : NAMES)
        {
            byte[] kek = random(24);
            SecretKey cek = new SecretKeySpec(random(24), "DESede");
            Cipher w = Cipher.getInstance(name, JSL);
            w.init(Cipher.WRAP_MODE, key(kek));
            byte[] wrapped = w.wrap(cek);
            Cipher u = Cipher.getInstance(name, BC);
            u.init(Cipher.UNWRAP_MODE, key(kek));
            Assertions.assertArrayEquals(cek.getEncoded(), u.unwrap(wrapped, "DESede", Cipher.SECRET_KEY).getEncoded(),
                    name);

            Cipher bw = Cipher.getInstance(name, BC);
            bw.init(Cipher.WRAP_MODE, key(kek));
            Cipher ju = Cipher.getInstance(name, JSL);
            ju.init(Cipher.UNWRAP_MODE, key(kek));
            Key back = ju.unwrap(bw.wrap(cek), "DESede", Cipher.SECRET_KEY);
            Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(), name);
        }
    }

    /** Two wraps of one key differ (fresh IV each time), and the caller's SecureRandom is the one drawn from. */
    @Test
    public void eachWrapDrawsAFreshIvFromTheCallersSecureRandom() throws Exception
    {
        byte[] kek = random(24);
        byte[] cek = random(24);
        Counting counting = new Counting();
        Cipher c = Cipher.getInstance("DESedeWrap", JSL);
        c.init(Cipher.ENCRYPT_MODE, key(kek), counting);
        byte[] first = c.doFinal(cek);
        Assertions.assertEquals(8, counting.served, "the first wrap draws its IV from the caller's SecureRandom");
        byte[] second = c.doFinal(cek);
        Assertions.assertEquals(16, counting.served, "the second wrap draws again from the same SecureRandom");
        Assertions.assertFalse(Arrays.areEqual(first, second), "two wraps of one key must differ");
        Assertions.assertArrayEquals(cek, unwrap(BC, "DESedeWrap", kek, first));
        Assertions.assertArrayEquals(cek, unwrap(BC, "DESedeWrap", kek, second));

        Counting unwrapRandom = new Counting();
        Cipher d = Cipher.getInstance("DESedeWrap", JSL);
        d.init(Cipher.DECRYPT_MODE, key(kek), unwrapRandom);
        Assertions.assertArrayEquals(cek, d.doFinal(first));
        Assertions.assertEquals(0, unwrapRandom.served, "unwrap draws no random bytes");
    }

    /** Any split of the input through update gives the RFC's answer, and of the wrapped input the RFC's key. */
    @Test
    public void chunkedInputAgreesWithTheKnownAnswer() throws Exception
    {
        int[][] splits = {{1}, {7}, {8}, {9}, {23}, {5, 11}, {3, 3, 3}};
        for (int[] split : splits)
        {
            StringBuilder label = new StringBuilder("split");
            for (int n : split)
            {
                label.append(' ').append(n);
            }
            Cipher c = Cipher.getInstance("DESedeWrap", JSL);
            c.init(Cipher.ENCRYPT_MODE, key(KEK), new FixedBytes(IV));
            Assertions.assertArrayEquals(RESULT, feed(c, CEK, split), label + " wrap");
            Cipher d = Cipher.getInstance("DESedeWrap", JSL);
            d.init(Cipher.DECRYPT_MODE, key(KEK));
            Assertions.assertArrayEquals(CEK, feed(d, RESULT, split), label + " unwrap");
        }
    }

    private static byte[] feed(Cipher c, byte[] in, int[] split) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        int i = 0;
        while (off < in.length)
        {
            int n = Math.min(split[i++ % split.length], in.length - off);
            byte[] part = c.update(in, off, n);
            if (part != null)
            {
                out.write(part);
            }
            off += n;
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    /** A wrap of a length that is not a non-zero multiple of 8: ours and BouncyCastle's types, in both modes. */
    @Test
    public void wrapLengthRefusals() throws Exception
    {
        byte[] kek = random(24);
        for (int len : new int[]{7, 9, 25})
        {
            byte[] cek = random(len);
            IllegalBlockSizeException ours = assertThrows(IllegalBlockSizeException.class,
                    () -> wrap(JSL, "DESedeWrap", kek, cek), "len " + len);
            Assertions.assertEquals("invalid key wrap input length", ours.getMessage());
            assertThrows(IllegalBlockSizeException.class, () -> wrap(BC, "DESedeWrap", kek, cek), "BC len " + len);

            // WRAP_MODE: BouncyCastle raises a raw IllegalStateException, outside the JCE contract; ours is typed.
            for (String provider : new String[]{JSL, BC})
            {
                Cipher w = Cipher.getInstance("DESedeWrap", provider);
                w.init(Cipher.WRAP_MODE, key(kek));
                SecretKey odd = new SecretKeySpec(cek, "AES");
                Class<? extends Throwable> want = JSL.equals(provider) ? IllegalBlockSizeException.class
                        : IllegalStateException.class;
                assertThrows(want, () -> w.wrap(odd), provider + " WRAP_MODE len " + len);
            }
        }

        // An empty wrap: ours refuses, BouncyCastle returns a 16-byte blob.
        assertThrows(IllegalBlockSizeException.class, () -> wrap(JSL, "DESedeWrap", kek, new byte[0]));
        Assertions.assertEquals(16, wrap(BC, "DESedeWrap", kek, new byte[0]).length);
    }

    /** An unwrap of a short, misaligned or corrupted input is BadPaddingException, InvalidKeyException via unwrap. */
    @Test
    public void unwrapRefusals() throws Exception
    {
        byte[] kek = random(24);
        byte[] good = wrap(JSL, "DESedeWrap", kek, random(24));
        byte[] corrupted = Arrays.clone(good);
        corrupted[corrupted.length / 2] ^= 1;
        byte[][] bad = {new byte[8], new byte[16], new byte[23], new byte[31], corrupted};
        for (byte[] in : bad)
        {
            String label = "len " + in.length;
            for (String provider : new String[]{JSL, BC})
            {
                assertThrows(BadPaddingException.class, () -> unwrap(provider, "DESedeWrap", kek, in),
                        provider + " " + label);
                Cipher u = Cipher.getInstance("DESedeWrap", provider);
                u.init(Cipher.UNWRAP_MODE, key(kek));
                assertThrows(InvalidKeyException.class, () -> u.unwrap(in, "DESede", Cipher.SECRET_KEY),
                        provider + " UNWRAP_MODE " + label);
            }
        }
    }

    /**
     * KEK length: ours takes the 24-byte three-key KEK only and refuses at init; BouncyCastle also takes a 16-byte
     * KEK, and refuses the others late, at doFinal.
     */
    @Test
    public void kekLengthRefusals() throws Exception
    {
        byte[] cek = random(24);
        for (int len : new int[]{8, 16, 23, 25, 32})
        {
            byte[] kek = random(len);
            Cipher ours = Cipher.getInstance("DESedeWrap", JSL);
            assertThrows(InvalidKeyException.class, () -> ours.init(Cipher.ENCRYPT_MODE, key(kek)), "len " + len);
            Cipher bc = Cipher.getInstance("DESedeWrap", BC);
            bc.init(Cipher.ENCRYPT_MODE, key(kek));
            if (len == 16)
            {
                Assertions.assertEquals(40, bc.doFinal(cek).length, "BC takes a two-key KEK");
            }
            else
            {
                assertThrows(IllegalBlockSizeException.class, () -> bc.doFinal(cek), "BC len " + len);
            }
        }
    }

    /**
     * The KeyGenerator name BouncyCastle 1.87 registers for the wrap resolves to the DESede generator, and its key
     * wraps and unwraps; BouncyCastle's same name gives a key of the same size.
     */
    @Test
    public void theWrapKeyGeneratorNameMakesAWrappingKey() throws Exception
    {
        Provider jsl = Security.getProvider(JSL);
        Assertions.assertEquals(jsl.getService("KeyGenerator", "DESede").getClassName(),
                jsl.getService("KeyGenerator", "DESedeWrap").getClassName());
        KeyGenerator ours = KeyGenerator.getInstance("DESedeWrap", JSL);
        Assertions.assertEquals(JSL, ours.getProvider().getName());
        SecretKey kek = ours.generateKey();
        Assertions.assertEquals(24, kek.getEncoded().length);
        Assertions.assertEquals(24, KeyGenerator.getInstance("DESedeWrap", BC).generateKey().getEncoded().length);

        byte[] cek = random(24);
        byte[] wrapped = wrap(JSL, "DESedeWrap", kek.getEncoded(), cek);
        Assertions.assertArrayEquals(cek, unwrap(BC, "DESedeWrap", kek.getEncoded(), wrapped));
        Assertions.assertFalse(Arrays.areEqual(kek.getEncoded(), ours.generateKey().getEncoded()));
    }

    /** Throws on its first draw and serves random bytes after, counting what it served. */
    static final class FailsOnce extends SecureRandom
    {
        static final String MESSAGE = "the first draw fails";
        int calls;
        int served;

        @Override
        public void nextBytes(byte[] out)
        {
            if (calls++ == 0)
            {
                throw new IllegalStateException(MESSAGE);
            }
            super.nextBytes(out);
            served += out.length;
        }
    }

    /**
     * A wrap whose IV draw fails: the call fails with the caller's exception as its cause and returns nothing; the
     * same instance then wraps correctly, and a later operation on this thread draws from its own SecureRandom, so
     * the up-call did not outlive the failed call.
     */
    @Test
    public void aFailedIvDrawLeavesTheInstanceUsable() throws Exception
    {
        byte[] kek = random(24);
        byte[] cek = random(24);
        FailsOnce fails = new FailsOnce();
        Cipher c = Cipher.getInstance("DESedeWrap", JSL);
        c.init(Cipher.ENCRYPT_MODE, key(kek), fails);
        byte[] out = new byte[64];
        Arrays.fill(out, (byte) 0x5a);
        OpenSSLException e = assertThrows(OpenSSLException.class, () -> c.doFinal(cek, 0, cek.length, out, 0));
        Assertions.assertEquals(OpenSSLException.class, e.getClass());
        Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
        Assertions.assertTrue(e.getMessage().contains("rand up-call failed"), e.getMessage());
        Assertions.assertEquals(IllegalStateException.class, e.getCause().getClass());
        Assertions.assertEquals(FailsOnce.MESSAGE, e.getCause().getMessage());
        for (byte b : out)
        {
            Assertions.assertEquals((byte) 0x5a, b, "a failed wrap writes nothing");
        }

        byte[] second = c.doFinal(cek);
        Assertions.assertEquals(2, fails.calls);
        Assertions.assertEquals(8, fails.served);
        Assertions.assertArrayEquals(cek, unwrap(BC, "DESedeWrap", kek, second));

        Counting own = new Counting();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", JSL);
        kpg.initialize(new ECGenParameterSpec("P-256"), own);
        kpg.generateKeyPair();
        Assertions.assertTrue(own.served > 0, "a later operation draws from its own SecureRandom");
        Assertions.assertEquals(2, fails.calls, "and not from the wrap's");
    }

    /**
     * A supplied IV: ours refuses it in every mode, OpenSSL having no way to take one; BouncyCastle uses an 8-byte
     * IV for wrapping, so two of its wraps with one IV are equal, and refuses one for unwrapping.
     */
    @Test
    public void aSuppliedIvIsRefused() throws Exception
    {
        byte[] kek = random(24);
        byte[] cek = random(24);
        IvParameterSpec iv = new IvParameterSpec(random(8));
        int[] modes = {Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE, Cipher.WRAP_MODE, Cipher.UNWRAP_MODE};
        for (int mode : modes)
        {
            Cipher ours = Cipher.getInstance("DESedeWrap", JSL);
            InvalidAlgorithmParameterException e = assertThrows(InvalidAlgorithmParameterException.class,
                    () -> ours.init(mode, key(kek), iv), "mode " + mode);
            Assertions.assertEquals("mode takes no iv", e.getMessage());
        }

        Cipher bc1 = Cipher.getInstance("DESedeWrap", BC);
        bc1.init(Cipher.ENCRYPT_MODE, key(kek), iv);
        Cipher bc2 = Cipher.getInstance("DESedeWrap", BC);
        bc2.init(Cipher.ENCRYPT_MODE, key(kek), iv);
        byte[] first = bc1.doFinal(cek);
        Assertions.assertArrayEquals(first, bc2.doFinal(cek), "BC wraps deterministically under a supplied IV");
        Assertions.assertArrayEquals(cek, unwrap(JSL, "DESedeWrap", kek, first), "ours unwraps it");
        for (int mode : new int[]{Cipher.DECRYPT_MODE, Cipher.UNWRAP_MODE})
        {
            Cipher bc = Cipher.getInstance("DESedeWrap", BC);
            InvalidKeyException e = assertThrows(InvalidKeyException.class, () -> bc.init(mode, key(kek), iv),
                    "BC mode " + mode);
            Assertions.assertEquals("You should not supply an IV for unwrapping", e.getMessage());
        }
    }

    /**
     * The wrap is also reached as DESede/WRAP on the plain DESede service, as AES/WRAP is on the plain AES service
     * (measured on the tree before this mode); the padding name is not applied. BouncyCastle serves neither.
     * This pins present behaviour, shared with the AES wrap modes, and does not make these names supported surface.
     */
    @Test
    public void theWrapModeOnThePlainDesedeServiceIsTheSameWrap() throws Exception
    {
        byte[] kek = random(24);
        byte[] cek = random(24);
        for (String t : new String[]{"DESede/WRAP/NoPadding", "DESede/WRAP/PKCS5Padding"})
        {
            Cipher c = Cipher.getInstance(t, JSL);
            c.init(Cipher.ENCRYPT_MODE, key(kek));
            byte[] wrapped = c.doFinal(cek);
            Assertions.assertEquals(cek.length + 16, wrapped.length, t);
            Assertions.assertArrayEquals(cek, unwrap(BC, "DESedeWrap", kek, wrapped), t);
            assertThrows(NoSuchAlgorithmException.class, () -> Cipher.getInstance(t, BC), "BC " + t);
        }
        Cipher aes = Cipher.getInstance("AES/WRAP/NoPadding", JSL);
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(random(16), "AES"));
        Assertions.assertEquals(32, aes.doFinal(random(24)).length, "the AES precedent");
    }

    /** One instance stays correct across operations and after a refused unwrap. */
    @Test
    public void oneInstanceStaysCorrectAcrossOperationsAndAfterFailure() throws Exception
    {
        byte[] kek = random(24);
        Cipher d = Cipher.getInstance("DESedeWrap", JSL);
        d.init(Cipher.DECRYPT_MODE, key(kek));
        for (int t = 0; t < TRIALS; t++)
        {
            byte[] cek = random(24);
            byte[] wrapped = wrap(BC, "DESedeWrap", kek, cek);
            byte[] corrupted = Arrays.clone(wrapped);
            corrupted[0] ^= 1;
            assertThrows(BadPaddingException.class, () -> d.doFinal(corrupted));
            Assertions.assertArrayEquals(cek, d.doFinal(wrapped), "trial " + t);
        }
    }
}
