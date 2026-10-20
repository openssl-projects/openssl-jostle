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

package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Duration;

/**
 * KDF cells shared by the base and FIPS tests, each taking the NI or the provider name it drives. Every expected
 * code here is the same on both bridges and under every module.
 */
public final class KdfCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int DIGEST = ErrorCode.JO_KDF_PBE_UNKNOWN_DIGEST.getCode();
    private static final int MODE = ErrorCode.JO_KDF_UNKNOWN_MODE.getCode();
    private static final int MAC = ErrorCode.JO_KDF_UNKNOWN_MAC.getCode();
    private static final int TYPE = ErrorCode.JO_KDF_SSHKDF_TYPE_INVALID.getCode();
    private static final int ZERO_LEN = ErrorCode.JO_OUTPUT_LEN_IS_ZERO.getCode();
    private static final int OPENSSL = ErrorCode.JO_OPENSSL_ERROR.getCode();

    private static final String SHA256 = "SHA2-256";

    /** A SecretKeyFactory derive through a named provider, returning the key's encoding. */
    public interface Deriver
    {
        byte[] derive(String provider, String alg, KeySpec spec) throws Exception;
    }

    private KdfCells()
    {
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    /** One fixed set of inputs per KDF, so a window can be compared with a separate derivation. */
    private static final class Inputs
    {
        final byte[] password = random(16);
        final byte[] salt = random(16);
        final byte[] ikm = random(32);
        final byte[] info = random(8);
        final byte[] key = random(32);
        final byte[] key16 = random(16);
        final byte[] label = random(8);
        final byte[] context = random(8);
        final byte[] xcghash = random(32);
        final byte[] session = random(32);

        int pbkdf2(KdfNI ni, String digest, byte[] out, int off, int len)
        {
            return ni.pbkdf2(password, salt, 1000, digest, out, off, len);
        }

        int hkdf(KdfNI ni, String digest, byte[] out, int off, int len)
        {
            return ni.hkdf(ikm, salt, info, digest, out, off, len);
        }

        int kbkdf(KdfNI ni, String mode, String mac, String digest, String cipher, byte[] out, int off, int len)
        {
            return ni.kbkdf(mode, mac, digest, cipher, cipher == null ? key : key16, label, context, null, 32, 0, 0,
                    out, off, len);
        }

        int sskdf(KdfNI ni, String digest, byte[] out, int off, int len)
        {
            return ni.sskdf(digest, key, info, out, off, len);
        }

        int sshkdf(KdfNI ni, String digest, String type, byte[] out, int off, int len)
        {
            return ni.sshkdf(digest, key, xcghash, session, type, out, off, len);
        }
    }

    /** A name holding a NUL names nothing: each name parameter answers its own code, and the prefix alone works. */
    public static void embeddedNulNamesAreRefused(KdfNI ni)
    {
        Inputs in = new Inputs();
        byte[] out = new byte[32];
        for (String d : new String[]{SHA256 + "\u0000", SHA256 + "\u0000x", "\u0000" + SHA256})
        {
            Assertions.assertEquals(DIGEST, in.pbkdf2(ni, d, out, 0, 32), "pbkdf2 digest");
            Assertions.assertEquals(DIGEST, in.hkdf(ni, d, out, 0, 32), "hkdf digest");
            Assertions.assertEquals(DIGEST, in.kbkdf(ni, "COUNTER", "HMAC", d, null, out, 0, 32), "kbkdf digest");
            Assertions.assertEquals(DIGEST, in.sskdf(ni, d, out, 0, 32), "sskdf digest");
            Assertions.assertEquals(DIGEST, in.sshkdf(ni, d, "A", out, 0, 32), "sshkdf digest");
        }
        Assertions.assertEquals(DIGEST, in.kbkdf(ni, "COUNTER", "CMAC", null, "AES-128-CBC\u0000x", out, 0, 32),
                "kbkdf cipher");
        Assertions.assertEquals(MODE, in.kbkdf(ni, "COUNTER\u0000x", "HMAC", SHA256, null, out, 0, 32), "mode");
        Assertions.assertEquals(MAC, in.kbkdf(ni, "COUNTER", "HMAC\u0000x", SHA256, null, out, 0, 32), "mac");
        Assertions.assertEquals(TYPE, in.sshkdf(ni, SHA256, "A\u0000x", out, 0, 32), "type");

        // The same calls with the name before the NUL derive.
        Assertions.assertEquals(0, in.pbkdf2(ni, SHA256, out, 0, 32));
        Assertions.assertEquals(0, in.hkdf(ni, SHA256, out, 0, 32));
        Assertions.assertEquals(0, in.kbkdf(ni, "COUNTER", "HMAC", SHA256, null, out, 0, 32));
        Assertions.assertEquals(0, in.kbkdf(ni, "COUNTER", "CMAC", null, "AES-128-CBC", out, 0, 32));
        Assertions.assertEquals(0, in.sskdf(ni, SHA256, out, 0, 32));
        Assertions.assertEquals(0, in.sshkdf(ni, SHA256, "A", out, 0, 32));
    }

    /**
     * A digest the library cannot fetch, or one of size zero ("NULL", on which OpenSSL's SSHKDF loop never ends), is
     * refused before any KDF runs. Each call is time-limited so a regression fails instead of hanging the leg.
     */
    public static void unusableDigestsAreRefused(KdfNI ni)
    {
        Inputs in = new Inputs();
        for (String d : new String[]{"NULL", "NOPE"})
        {
            Assertions.assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
                byte[] out = new byte[32];
                Assertions.assertEquals(DIGEST, in.pbkdf2(ni, d, out, 0, 32), "pbkdf2 " + d);
                Assertions.assertEquals(DIGEST, in.hkdf(ni, d, out, 0, 32), "hkdf " + d);
                Assertions.assertEquals(DIGEST, in.kbkdf(ni, "COUNTER", "HMAC", d, null, out, 0, 32), "kbkdf " + d);
                Assertions.assertEquals(DIGEST, in.sskdf(ni, d, out, 0, 32), "sskdf " + d);
                Assertions.assertEquals(DIGEST, in.sshkdf(ni, d, "A", out, 0, 32), "sshkdf " + d);
            }, d);
        }
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ni.handleErrorCodes(in.sshkdf(ni, "NULL", "A", new byte[32], 0, 32)));
        Assertions.assertEquals("unknown digest", ex.getMessage());
    }

    /** A zero-length output is refused before any KDF runs, on all five. */
    public static void zeroLengthOutputIsRefused(KdfNI ni)
    {
        Inputs in = new Inputs();
        for (byte[] out : new byte[][]{new byte[0], new byte[32]})
        {
            Assertions.assertEquals(ZERO_LEN, in.pbkdf2(ni, SHA256, out, 0, 0), "pbkdf2");
            Assertions.assertEquals(ZERO_LEN, in.hkdf(ni, SHA256, out, 0, 0), "hkdf");
            Assertions.assertEquals(ZERO_LEN, in.kbkdf(ni, "COUNTER", "HMAC", SHA256, null, out, 0, 0), "kbkdf");
            Assertions.assertEquals(ZERO_LEN, in.sskdf(ni, SHA256, out, 0, 0), "sskdf");
            Assertions.assertEquals(ZERO_LEN, in.sshkdf(ni, SHA256, "A", out, 0, 0), "sshkdf");
        }
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ni.handleErrorCodes(in.pbkdf2(ni, SHA256, new byte[1], 0, 0)));
        Assertions.assertEquals("output len is zero", ex.getMessage());
    }

    /** SSHKDF refuses in its parameter order: digest, key, exchange hash, session id, type. */
    public static void sshkdfRefusesInParameterOrder(KdfNI ni)
    {
        byte[] k = random(32);
        byte[] h = random(32);
        byte[] s = random(32);
        byte[] out = new byte[32];
        Assertions.assertEquals(ErrorCode.JO_KDF_SECRET_NULL.getCode(),
                ni.sshkdf(SHA256, null, h, s, null, out, 0, 32), "key and type null");
        Assertions.assertEquals(ErrorCode.JO_KDF_SSHKDF_XCGHASH_NULL.getCode(),
                ni.sshkdf(SHA256, k, null, s, null, out, 0, 32), "exchange hash and type null");
        Assertions.assertEquals(ErrorCode.JO_KDF_SSHKDF_SESSION_ID_NULL.getCode(),
                ni.sshkdf(SHA256, k, h, null, null, out, 0, 32), "session id and type null");
        Assertions.assertEquals(TYPE, ni.sshkdf(SHA256, k, h, s, null, null, 0, 32), "type and output null");
    }

    /** SSHKDF derives with an empty exchange hash, and the hash is an input: one byte more changes the key. */
    public static void sshkdfDerivesWithAnEmptyExchangeHash(KdfNI ni)
    {
        byte[] k = random(32);
        byte[] s = random(32);
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        Assertions.assertEquals(0, ni.sshkdf(SHA256, k, new byte[0], s, "A", a, 0, 32));
        Assertions.assertEquals(0, ni.sshkdf(SHA256, k, new byte[1], s, "A", b, 0, 32));
        Assertions.assertFalse(Arrays.areEqual(a, b));
    }

    private interface Derive
    {
        int into(byte[] out, int off, int len);
    }

    private static void refusedLeavesTheArray(String what, Derive d, int len)
    {
        byte[] buf = random(len + 16);
        byte[] before = Arrays.clone(buf);
        Assertions.assertEquals(OPENSSL, d.into(buf, 8, len), what + " refused");
        Assertions.assertArrayEquals(before, buf, what + ": the caller's array changed");
    }

    private static void succeededWritesOnlyTheWindow(String what, Derive d, int len)
    {
        byte[] alone = new byte[len];
        Assertions.assertEquals(0, d.into(alone, 0, len), what);
        byte[] buf = random(len + 16);
        byte[] before = Arrays.clone(buf);
        Assertions.assertEquals(0, d.into(buf, 8, len), what);
        // Arrays is qualified where the JDK's is meant: jostle's of that name is imported
        Assertions.assertArrayEquals(java.util.Arrays.copyOfRange(before, 0, 8),
                java.util.Arrays.copyOfRange(buf, 0, 8), what + " prefix");
        Assertions.assertArrayEquals(alone, java.util.Arrays.copyOfRange(buf, 8, 8 + len), what + " window");
        Assertions.assertArrayEquals(java.util.Arrays.copyOfRange(before, 8 + len, buf.length),
                java.util.Arrays.copyOfRange(buf, 8 + len, buf.length), what + " suffix");
    }

    /**
     * A derive the library refuses leaves the caller's whole array as it was; one it accepts writes the window
     * and nothing else. Each refusal is raised inside the library's derive, on every module.
     */
    public static void outputIsWrittenOnlyOnSuccess(KdfNI ni)
    {
        Inputs in = new Inputs();
        refusedLeavesTheArray("pbkdf2 iterations 0",
                (o, off, len) -> ni.pbkdf2(in.password, in.salt, 0, SHA256, o, off, len), 32);
        refusedLeavesTheArray("hkdf beyond 255 blocks",
                (o, off, len) -> in.hkdf(ni, SHA256, o, off, len), 255 * 32 + 1);
        refusedLeavesTheArray("kbkdf counter mode with a seed shorter than the MAC",
                (o, off, len) -> ni.kbkdf("COUNTER", "HMAC", SHA256, null, in.key, in.label, in.context,
                        random(16), 32, 0, 0, o, off, len), 32);
        refusedLeavesTheArray("sskdf empty secret",
                (o, off, len) -> ni.sskdf(SHA256, new byte[0], in.info, o, off, len), 32);
        refusedLeavesTheArray("sshkdf type G",
                (o, off, len) -> in.sshkdf(ni, SHA256, "G", o, off, len), 32);

        succeededWritesOnlyTheWindow("pbkdf2", (o, off, len) -> in.pbkdf2(ni, SHA256, o, off, len), 32);
        succeededWritesOnlyTheWindow("hkdf", (o, off, len) -> in.hkdf(ni, SHA256, o, off, len), 32);
        succeededWritesOnlyTheWindow("kbkdf",
                (o, off, len) -> in.kbkdf(ni, "COUNTER", "HMAC", SHA256, null, o, off, len), 32);
        succeededWritesOnlyTheWindow("sskdf", (o, off, len) -> in.sskdf(ni, SHA256, o, off, len), 32);
        succeededWritesOnlyTheWindow("sshkdf", (o, off, len) -> in.sshkdf(ni, SHA256, "A", o, off, len), 32);
    }

    /**
     * The factory refuses a request needing more than 2^r - 1 blocks of the MAC's size, in both modes; SP 800-108r1
     * section 5.1 requires n = ceil(L / h) <= 2^r - 1. With r = 16 the same lengths derive.
     */
    public static void kbkdfBlockBound(String provider, Deriver f) throws Exception
    {
        String[][] prfs = {{"KBKDF-HMAC-SHA256", "32"}, {"KBKDF-CMAC-AES128", "16"}};
        for (String[] prf : prfs)
        {
            String alg = prf[0];
            int h = Integer.parseInt(prf[1]);
            byte[] key = random(h == 16 ? 16 : 32);
            for (KBKDFParameterSpec.Mode mode : KBKDFParameterSpec.Mode.values())
            {
                byte[] iv = mode == KBKDFParameterSpec.Mode.FEEDBACK ? random(h) : null;
                String what = alg + " " + mode;
                Assertions.assertEquals(255 * h, f.derive(provider, alg,
                        new KBKDFParameterSpec(key, null, null, iv, mode, 8, false, false, 255 * h)).length, what);
                InvalidKeySpecException ex = Assertions.assertThrows(InvalidKeySpecException.class,
                        () -> f.derive(provider, alg,
                                new KBKDFParameterSpec(key, null, null, iv, mode, 8, false, false, 255 * h + 1)), what);
                Assertions.assertEquals("output length " + (255 * h + 1) + " needs 256 blocks of " + h
                        + " bytes; r = 8 allows 255", ex.getMessage(), what);
                Assertions.assertEquals(255 * h + 1, f.derive(provider, alg,
                        new KBKDFParameterSpec(key, null, null, iv, mode, 16, false, false, 255 * h + 1)).length, what);
            }
        }
    }

    /**
     * Operations-test build. JNI copies the secret input and the output of every KDF through the cleansing helper,
     * on success and on a refused derive; FFM takes no ledgered copy.
     */
    public static void secretCopiesAreCleansed(KdfNI ni, OperationsTestNI ops)
    {
        Inputs in = new Inputs();
        Derive[] calls = {
                (o, off, len) -> in.pbkdf2(ni, SHA256, o, off, len),
                (o, off, len) -> in.hkdf(ni, SHA256, o, off, len),
                (o, off, len) -> in.kbkdf(ni, "COUNTER", "HMAC", SHA256, null, o, off, len),
                (o, off, len) -> in.sskdf(ni, SHA256, o, off, len),
                (o, off, len) -> in.sshkdf(ni, SHA256, "A", o, off, len),
                (o, off, len) -> in.sshkdf(ni, SHA256, "G", o, off, len)};
        int expected = Loader.isFFM() ? 0 : 2;
        for (int i = 0; i != calls.length; i++)
        {
            ops.ledgerReset();
            calls[i].into(new byte[32], 0, 32);
            for (OperationsTestNI.LedgerType t : new OperationsTestNI.LedgerType[]{
                    OperationsTestNI.LedgerType.SECRET_BYTEARRAY, OperationsTestNI.LedgerType.SECRET_CLEANSE})
            {
                Assertions.assertEquals(expected, ops.ledgerCreated(t), "call " + i + " " + t + " created");
                Assertions.assertEquals(expected, ops.ledgerDestroyed(t), "call " + i + " " + t + " destroyed");
            }
        }
    }
}
