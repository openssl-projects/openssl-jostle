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

package org.openssl.jostle.test.mac;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.spec.KMACParameterSpec;
import org.openssl.jostle.util.ops.OperationsTestNI;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;

/**
 * MAC cells shared by the base and FIPS tests, each taking the NIs or the provider name it drives.
 */
public final class MacCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The KMAC output ceiling, in bytes, that the native layer refuses beyond. */
    public static final int KMAC_MAX_OUTPUT_BYTES = 1024 * 1024;

    private static final String GMAC_SPENT = "GMAC needs a new init with a new nonce";

    private static final String NONCE_REUSED = "nonce reused under the same key";

    private MacCells()
    {
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static long mac(MacServiceNI ni, String name, String function)
    {
        int[] err = new int[1];
        long ref = ni.ni_allocateMac(name, function, err);
        Assertions.assertEquals(0, err[0], "ni_allocateMac(" + name + ", " + function + ")");
        Assertions.assertNotEquals(0L, ref);
        return ref;
    }

    private static long hmac(MacServiceNI ni)
    {
        return mac(ni, "HMAC", "SHA-256");
    }

    /** HMAC-SHA256 from BouncyCastle's lightweight API, which shares no code with either library. */
    private static byte[] hmacReference(byte[] key, byte[] msg)
    {
        HMac h = new HMac(new SHA256Digest());
        h.init(new KeyParameter(key));
        h.update(msg, 0, msg.length);
        byte[] out = new byte[h.getMacSize()];
        h.doFinal(out, 0);
        return out;
    }

    /** KMAC from BouncyCastle's lightweight API at an explicit output length. */
    private static byte[] kmacReference(int bits, byte[] key, byte[] custom, byte[] msg, int outLen)
    {
        KMAC k = new KMAC(bits, custom);
        k.init(new KeyParameter(key));
        k.update(msg, 0, msg.length);
        byte[] out = new byte[outLen];
        k.doFinal(out, 0, outLen);
        return out;
    }

    private static long md(MDServiceNI ni)
    {
        int[] err = new int[1];
        long ref = ni.ni_allocateDigest("SHA2-256", 0, err);
        Assertions.assertEquals(0, err[0], "ni_allocateDigest");
        return ref;
    }

    private static long ccm(CCMCipherNI ni)
    {
        int[] err = new int[1];
        long ref = ni.ni_makeInstance(CCMCipherNI.AES128, err);
        Assertions.assertEquals(0, err[0], "ni_makeInstance(AES128)");
        return ref;
    }

    private static long bc(BlockCipherNI ni)
    {
        return ni.makeInstance(OSSLCipher.AES128.ordinal(), OSSLMode.CBC.ordinal(), 0);
    }

    /** Every MAC entry taking a handle refuses a foreign handle with the wrong-kind code. */
    private static void refusedByEveryMacEntry(MacServiceNI mac, long foreign, String what)
    {
        int wrong = ErrorCode.JO_MAC_CTX_WRONG_KIND.getCode();
        int[] err = new int[1];
        Assertions.assertEquals(0L, mac.ni_copyMac(foreign, err), what + " copy handle");
        Assertions.assertEquals(wrong, err[0], what + " copy");
        Assertions.assertEquals(wrong, mac.ni_init(foreign, random(32), null, null, 0), what + " init");
        Assertions.assertEquals(wrong, mac.ni_updateByte(foreign, (byte) 1), what + " updateByte");
        Assertions.assertEquals(wrong, mac.ni_updateBytes(foreign, new byte[4], 0, 4), what + " updateBytes");
        Assertions.assertEquals(wrong, mac.ni_doFinal(foreign, new byte[32], 0), what + " doFinal");
        Assertions.assertEquals(wrong, mac.ni_getMacLength(foreign), what + " getMacLength");
        Assertions.assertEquals(wrong, mac.ni_macLengthMeta(foreign), what + " macLengthMeta");
        Assertions.assertEquals(wrong, mac.ni_reset(foreign), what + " reset");
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mac.getMacLength(foreign));
        Assertions.assertEquals("handle is not a MAC context", ex.getMessage(), what);
        mac.ni_dispose(foreign);
    }

    /**
     * A live digest, block cipher or CCM handle is refused at every MAC entry, and a MAC handle at those families'
     * entries; dispose through the wrong family frees nothing, so all four stay usable.
     */
    public static void wrongKindRefusedBothWays(MacServiceNI mac, MDServiceNI md, BlockCipherNI bc,
                                                CCMCipherNI ccm)
    {
        long macRef = hmac(mac);
        long mdRef = md(md);
        long bcRef = bc(bc);
        long ccmRef = ccm(ccm);
        try
        {
            refusedByEveryMacEntry(mac, mdRef, "digest handle");
            refusedByEveryMacEntry(mac, bcRef, "block cipher handle");
            refusedByEveryMacEntry(mac, ccmRef, "CCM handle");

            Assertions.assertEquals(ErrorCode.JO_MD_CTX_WRONG_KIND.getCode(), md.ni_updateByte(macRef, (byte) 1),
                    "digest updateByte");
            Assertions.assertEquals(ErrorCode.JO_MD_CTX_WRONG_KIND.getCode(), md.ni_reset(macRef), "digest reset");
            Assertions.assertEquals(ErrorCode.JO_BLOCK_CIPHER_CTX_WRONG_KIND.getCode(),
                    bc.ni_init(macRef, Cipher.ENCRYPT_MODE, random(16), random(16), 0), "block cipher init");
            Assertions.assertEquals(ErrorCode.JO_CCM_CTX_WRONG_KIND.getCode(),
                    ccm.ni_init(macRef, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8), "CCM init");
            md.ni_dispose(macRef);
            bc.ni_dispose(macRef);
            ccm.ni_dispose(macRef);

            // All four still work.
            byte[] key = random(32);
            byte[] msg = random(45);
            Assertions.assertEquals(0, mac.ni_init(macRef, key, null, null, 0));
            Assertions.assertEquals(0, mac.ni_updateBytes(macRef, msg, 0, msg.length));
            byte[] tag = new byte[32];
            Assertions.assertEquals(32, mac.ni_doFinal(macRef, tag, 0));
            Assertions.assertArrayEquals(hmacReference(key, msg), tag);
            Assertions.assertEquals(32, md.ni_digest(mdRef, new byte[32], 0, 32));
            Assertions.assertEquals(0, bc.ni_init(bcRef, Cipher.ENCRYPT_MODE, random(16), random(16), 0));
            Assertions.assertEquals(0, ccm.ni_init(ccmRef, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8));
        }
        finally
        {
            mac.ni_dispose(macRef);
            md.ni_dispose(mdRef);
            bc.ni_dispose(bcRef);
            ccm.ni_dispose(ccmRef);
        }
    }

    /** A 0 handle is refused with the null-context code at every entry taking one, copy and reset included. */
    public static void nullHandleRefusedEverywhere(MacServiceNI mac)
    {
        int expected = ErrorCode.JO_MAC_CTX_IS_NULL.getCode();
        int[] err = new int[1];
        Assertions.assertEquals(0L, mac.ni_copyMac(0L, err), "copy handle");
        Assertions.assertEquals(expected, err[0], "copy");
        Assertions.assertEquals(expected, mac.ni_init(0L, random(32), null, null, 0), "init");
        // The handle is checked before the key, input and range checks.
        Assertions.assertEquals(expected, mac.ni_init(0L, null, null, null, -1), "init, other inputs bad");
        Assertions.assertEquals(expected, mac.ni_updateByte(0L, (byte) 1), "updateByte");
        Assertions.assertEquals(expected, mac.ni_updateBytes(0L, null, -1, -1), "updateBytes");
        Assertions.assertEquals(expected, mac.ni_doFinal(0L, null, -1), "doFinal");
        Assertions.assertEquals(expected, mac.ni_getMacLength(0L), "getMacLength");
        Assertions.assertEquals(expected, mac.ni_macLengthMeta(0L), "macLengthMeta");
        Assertions.assertEquals(expected, mac.ni_reset(0L), "reset");

        Runnable[] typed = {
                () -> mac.copyMac(0L),
                () -> mac.engineUpdate(0L, (byte) 1),
                () -> mac.engineUpdate(0L, new byte[4], 0, 4),
                () -> mac.doFinal(0L, new byte[32], 0),
                () -> mac.getMacLength(0L),
                () -> mac.macLengthMeta(0L),
                () -> mac.reset(0L)};
        for (Runnable r : typed)
        {
            IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class, r::run);
            Assertions.assertEquals("mac context is null", ex.getMessage());
        }
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mac.engineInit(0L, random(32), null, null, 0));
        Assertions.assertEquals("mac context is null", ex.getMessage());
        mac.ni_dispose(0L);
    }

    /** Reset on a 0 handle is a typed refusal on both bridges, not a silent success. */
    public static void resetOnANullHandleIsTyped(MacServiceNI mac)
    {
        Assertions.assertEquals(ErrorCode.JO_MAC_CTX_IS_NULL.getCode(), mac.ni_reset(0L));
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class, () -> mac.reset(0L));
        Assertions.assertEquals("mac context is null", ex.getMessage());
    }

    private static void allocateRefused(MacServiceNI mac, String name, String function, ErrorCode code,
                                        String message)
    {
        int[] err = new int[1];
        long ref = mac.ni_allocateMac(name, function, err);
        if (ref != 0)
        {
            mac.ni_dispose(ref);
        }
        String what = name.length() + "/" + function.length() + " chars";
        Assertions.assertEquals(0L, ref, "handle for " + what);
        Assertions.assertEquals(code.getCode(), err[0], "code for " + what);
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> mac.allocateMac(name, function));
        Assertions.assertEquals(message, ex.getMessage(), what);
    }

    /**
     * An empty name, a lone NUL and a name with an embedded NUL name nothing, for the MAC name and the function name
     * alike, on both bridges; the same names without the NUL allocate.
     */
    public static void embeddedNulNamesAreRefused(MacServiceNI mac)
    {
        for (String bad : new String[]{"HMAC\0x", "HMAC\0", "\0", ""})
        {
            allocateRefused(mac, bad, "SHA-256", ErrorCode.JO_NAME_NOT_FOUND, "name not found");
        }
        for (String bad : new String[]{"SHA-256\0x", "SHA-256\0", "\0", ""})
        {
            allocateRefused(mac, "HMAC", bad, ErrorCode.JO_MAC_FUNCTION_NOT_FOUND, "mac function name not found");
        }
        mac.ni_dispose(hmac(mac));
    }

    /** The JNI name scan refuses only the NUL encoding: other two-byte characters ending 0x80 pass to OpenSSL. */
    public static void nulScanSeesOnlyTheNulEncoding(MacServiceNI mac)
    {
        for (String function : new String[]{"SHA-256\u0100", "SHA-256\u00C0", "SHA-256\u0400"})
        {
            int[] err = new int[1];
            long ref = mac.ni_allocateMac("HMAC", function, err);
            try
            {
                Assertions.assertEquals(0, err[0], "allocate " + function.length());
                Assertions.assertNotEquals(0L, ref);
                // OpenSSL then knows no such digest.
                Assertions.assertEquals(ErrorCode.JO_OPENSSL_ERROR.getCode(),
                        mac.ni_init(ref, random(32), null, null, 0), "init " + function.length());
            }
            finally
            {
                mac.ni_dispose(ref);
            }
        }
        allocateRefused(mac, "HMAC\u0400", "SHA-256", ErrorCode.JO_NAME_NOT_FOUND, "name not found");
    }

    /** A MAC name OpenSSL does not know is not found, as for the digests, rather than an OpenSSL error. */
    public static void unknownMacNameIsNotFound(MacServiceNI mac)
    {
        allocateRefused(mac, "NOPE", "SHA-256", ErrorCode.JO_NAME_NOT_FOUND, "name not found");
        allocateRefused(mac, "ZZZZZZZ", "SHA-256", ErrorCode.JO_NAME_NOT_FOUND, "name not found");
    }

    /**
     * The largest KMAC output the ceiling allows inits and agrees with BouncyCastle; one byte more is refused, for
     * both KMACs; and two ordinary sizes agree with BouncyCastle through the JCE.
     */
    public static void kmacOutputAtTheBoundAndBeyond(MacServiceNI mac, String provider) throws Exception
    {
        for (int bits : new int[]{128, 256})
        {
            String name = "KMAC-" + bits;
            long ref = mac(mac, name, name);
            try
            {
                byte[] key = random(32);
                byte[] msg = random(77);
                Assertions.assertEquals(0, mac.ni_init(ref, key, null, null, KMAC_MAX_OUTPUT_BYTES), name);
                Assertions.assertEquals(KMAC_MAX_OUTPUT_BYTES, mac.ni_getMacLength(ref), name);
                Assertions.assertEquals(0, mac.ni_updateBytes(ref, msg, 0, msg.length));
                byte[] out = new byte[KMAC_MAX_OUTPUT_BYTES];
                Assertions.assertEquals(KMAC_MAX_OUTPUT_BYTES, mac.ni_doFinal(ref, out, 0));
                Assertions.assertArrayEquals(kmacReference(bits, key, null, msg, KMAC_MAX_OUTPUT_BYTES), out, name);

                Assertions.assertEquals(ErrorCode.JO_MAC_OUTPUT_LEN_INVALID.getCode(),
                        mac.ni_init(ref, key, null, null, KMAC_MAX_OUTPUT_BYTES + 1), name + " beyond");
                InvalidAlgorithmParameterException ex = Assertions.assertThrows(
                        InvalidAlgorithmParameterException.class,
                        () -> mac.engineInit(ref, key, null, null, KMAC_MAX_OUTPUT_BYTES + 1));
                Assertions.assertEquals("output length is too large", ex.getMessage());
            }
            finally
            {
                mac.ni_dispose(ref);
            }

            for (int outLen : new int[]{100, 4096})
            {
                byte[] key = random(32);
                byte[] custom = random(9);
                byte[] msg = random(1 + RANDOM.nextInt(300));
                Mac m = Mac.getInstance("KMAC" + bits, provider);
                m.init(new SecretKeySpec(key, "KMAC" + bits), new KMACParameterSpec(outLen * 8, custom));
                Assertions.assertEquals(outLen, m.getMacLength());
                Assertions.assertArrayEquals(kmacReference(bits, key, custom, msg, outLen), m.doFinal(msg),
                        "KMAC" + bits + " " + outLen);
            }
        }
    }

    /**
     * A KMAC spec the native layer refuses leaves no trace of its length: a fresh instance keeps the default, and
     * one that had an accepted length reports the default, as native has dropped it. A spec refused before native
     * changes nothing.
     */
    public static void refusedKmacSpecLeavesMacLengthUnchanged(String provider) throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(random(32), "KMAC128");
        KMACParameterSpec tooLong = new KMACParameterSpec((KMAC_MAX_OUTPUT_BYTES + 1) * 8, null);

        Mac fresh = Mac.getInstance("KMAC128", provider);
        int defaultLen = fresh.getMacLength();
        Assertions.assertEquals(32, defaultLen);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> fresh.init(key, tooLong));
        Assertions.assertEquals(defaultLen, fresh.getMacLength(), "fresh instance after a refused spec");

        Mac sized = Mac.getInstance("KMAC128", provider);
        sized.init(key, new KMACParameterSpec(512, null));
        Assertions.assertEquals(64, sized.getMacLength());
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> sized.init(key, new IvParameterSpec(new byte[16])));
        Assertions.assertEquals(64, sized.getMacLength(), "a spec refused in Java changes nothing");
        Assertions.assertThrows(InvalidAlgorithmParameterException.class, () -> sized.init(key, tooLong));
        Assertions.assertEquals(defaultLen, sized.getMacLength(), "after a refused native init");
    }

    /**
     * After final, update and final fail without a reset, on both bridges; reset restores the context, whose next
     * tag is the empty-input tag.
     */
    public static void finalThenUpdateWithoutResetFails(MacServiceNI mac)
    {
        long ref = hmac(mac);
        try
        {
            byte[] key = random(32);
            byte[] msg = random(33);
            Assertions.assertEquals(0, mac.ni_init(ref, key, null, null, 0));
            Assertions.assertEquals(0, mac.ni_updateBytes(ref, msg, 0, msg.length));
            byte[] tag = new byte[32];
            Assertions.assertEquals(32, mac.ni_doFinal(ref, tag, 0));
            Assertions.assertArrayEquals(hmacReference(key, msg), tag);

            int openssl = ErrorCode.JO_OPENSSL_ERROR.getCode();
            Assertions.assertEquals(openssl, mac.ni_updateBytes(ref, msg, 0, msg.length), "update after final");
            Assertions.assertEquals(openssl, mac.ni_doFinal(ref, new byte[32], 0), "final after final");

            Assertions.assertEquals(0, mac.ni_reset(ref));
            byte[] empty = new byte[32];
            Assertions.assertEquals(32, mac.ni_doFinal(ref, empty, 0));
            Assertions.assertArrayEquals(hmacReference(key, new byte[0]), empty, "empty-input tag after reset");
        }
        finally
        {
            mac.ni_dispose(ref);
        }
    }

    /** Reset after final restores the context, whose next tag is the empty-input tag. */
    public static void resetAfterFinalGivesTheEmptyInputTag(MacServiceNI mac)
    {
        long ref = hmac(mac);
        try
        {
            byte[] key = random(32);
            byte[] msg = random(33);
            Assertions.assertEquals(0, mac.ni_init(ref, key, null, null, 0));
            Assertions.assertEquals(0, mac.ni_updateBytes(ref, msg, 0, msg.length));
            byte[] tag = new byte[32];
            Assertions.assertEquals(32, mac.ni_doFinal(ref, tag, 0));
            Assertions.assertArrayEquals(hmacReference(key, msg), tag);

            Assertions.assertEquals(0, mac.ni_reset(ref));
            byte[] empty = new byte[32];
            Assertions.assertEquals(32, mac.ni_doFinal(ref, empty, 0));
            Assertions.assertArrayEquals(hmacReference(key, new byte[0]), empty, "empty-input tag after reset");
        }
        finally
        {
            mac.ni_dispose(ref);
        }
    }

    /** A copy of a context never initialised is not initialised either: length and reset refuse. */
    public static void copyOfAnUninitialisedContextIsNotInitialised(MacServiceNI mac)
    {
        long ref = hmac(mac);
        int[] err = new int[1];
        long copy = mac.ni_copyMac(ref, err);
        try
        {
            Assertions.assertEquals(0, err[0]);
            Assertions.assertNotEquals(0L, copy);
            int notInit = ErrorCode.JO_NOT_INITIALIZED.getCode();
            Assertions.assertEquals(notInit, mac.ni_getMacLength(copy), "length");
            Assertions.assertEquals(notInit, mac.ni_reset(copy), "reset");
            Assertions.assertEquals(notInit, mac.ni_reset(ref), "source reset");
        }
        finally
        {
            mac.ni_dispose(copy);
            mac.ni_dispose(ref);
        }
    }

    /**
     * A GMAC context finalized once is spent at the NI, with no reset involved: update, final and the length
     * refuse until a new init, and a new nonce then gives a fresh context's tag.
     */
    public static void gmacFinalSpendsTheContext(MacServiceNI mac)
    {
        long ref = mac(mac, "GMAC", "aes-gcm");
        long fresh = mac(mac, "GMAC", "aes-gcm");
        try
        {
            byte[] key = random(16);
            Assertions.assertEquals(0, mac.ni_init(ref, key, random(12), null, 0));
            Assertions.assertEquals(16, mac.ni_doFinal(ref, new byte[16], 0));

            int notInit = ErrorCode.JO_NOT_INITIALIZED.getCode();
            Assertions.assertEquals(notInit, mac.ni_updateByte(ref, (byte) 1), "updateByte");
            Assertions.assertEquals(notInit, mac.ni_doFinal(ref, new byte[16], 0), "doFinal");
            Assertions.assertEquals(notInit, mac.ni_getMacLength(ref), "getMacLength");

            byte[] iv = random(12);
            byte[] msg = random(29);
            Assertions.assertEquals(0, mac.ni_init(ref, key, iv, null, 0), "new nonce");
            Assertions.assertEquals(0, mac.ni_updateBytes(ref, msg, 0, msg.length));
            byte[] tag = new byte[16];
            Assertions.assertEquals(16, mac.ni_doFinal(ref, tag, 0));
            Assertions.assertEquals(0, mac.ni_init(fresh, key, iv, null, 0));
            Assertions.assertEquals(0, mac.ni_updateBytes(fresh, msg, 0, msg.length));
            byte[] expected = new byte[16];
            Assertions.assertEquals(16, mac.ni_doFinal(fresh, expected, 0));
            Assertions.assertArrayEquals(expected, tag, "against a fresh context");
        }
        finally
        {
            mac.ni_dispose(ref);
            mac.ni_dispose(fresh);
        }
    }

    /** A second doFinal on one Poly1305 instance equals BouncyCastle's tag and a fresh instance's. */
    public static void poly1305SecondDoFinalEqualsBcAndFresh(String provider) throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(random(32), "Poly1305");
        byte[] first = random(40);
        byte[] second = random(71);

        Mac ours = Mac.getInstance("POLY1305", provider);
        ours.init(key);
        Mac bc = Mac.getInstance("POLY1305", "BC");
        bc.init(key);
        Assertions.assertArrayEquals(bc.doFinal(first), ours.doFinal(first), "first tag");
        byte[] again = ours.doFinal(second);
        Assertions.assertArrayEquals(bc.doFinal(second), again, "second tag against BouncyCastle");

        Mac fresh = Mac.getInstance("POLY1305", provider);
        fresh.init(key);
        Assertions.assertArrayEquals(fresh.doFinal(second), again, "second tag against a fresh instance");
    }

    /** Init each algorithm cannot accept: a key the native layer refuses, or a null key for HMAC. */
    private static void refusedInit(Mac m, String alg)
    {
        Assertions.assertThrows(Exception.class, () -> {
            switch (alg)
            {
                case "HmacSHA256":
                    m.init(null);
                    break;
                case "AESGMAC":
                    m.init(new SecretKeySpec(new byte[15], "AES"), new IvParameterSpec(random(12)));
                    break;
                case "POLY1305":
                    m.init(new SecretKeySpec(new byte[31], "Poly1305"));
                    break;
                case "KMAC128":
                    m.init(new SecretKeySpec(new byte[3], "KMAC128"));
                    break;
                default:
                    m.init(new SecretKeySpec(new byte[15], "AES"));
            }
        }, alg);
    }

    /**
     * Mac.reset() before any init, and after a refused init, is accepted, as BouncyCastle and SunJCE accept it.
     */
    public static void resetBeforeInitIsANoOp(String provider, String... algorithms) throws Exception
    {
        for (String alg : algorithms)
        {
            Mac ours = Mac.getInstance(alg, provider);
            ours.reset();
            refusedInit(ours, alg);
            ours.reset();

            // A null key is refused by every provider, before any native layer.
            Mac bc = Mac.getInstance(alg, "BC");
            bc.reset();
            Assertions.assertThrows(Exception.class, () -> bc.init(null), alg + " on BC");
            bc.reset();

            if ("HmacSHA256".equals(alg))
            {
                Mac sun = Mac.getInstance(alg, "SunJCE");
                sun.reset();
                Assertions.assertThrows(Exception.class, () -> sun.init(null), alg + " on SunJCE");
                sun.reset();
            }
        }
    }

    private static Mac gmac(String provider, byte[] key, byte[] iv) throws Exception
    {
        Mac m = Mac.getInstance("AESGMAC", provider);
        m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return m;
    }

    private static void refusedSpent(Mac m, String what)
    {
        IllegalStateException ex = Assertions.assertThrows(IllegalStateException.class, () -> m.update((byte) 1),
                what + " update");
        if (!"BC".equals(m.getProvider().getName()))
        {
            Assertions.assertEquals(GMAC_SPENT, ex.getMessage(), what);
        }
        Assertions.assertThrows(IllegalStateException.class, m::doFinal, what + " doFinal");
    }

    /** After doFinal a GMAC instance refuses update and doFinal until a new init, as BouncyCastle's does. */
    public static void gmacRefusesAfterDoFinal(String provider) throws Exception
    {
        byte[] key = random(16);
        byte[] iv = random(12);
        for (String p : new String[]{provider, "BC"})
        {
            Mac m = gmac(p, key, iv);
            m.update(random(20));
            Assertions.assertEquals(16, m.doFinal().length);
            refusedSpent(m, p);
        }
    }

    /** After reset an initialised GMAC instance is spent as after doFinal, as BouncyCastle's is. */
    public static void gmacRefusesAfterReset(String provider) throws Exception
    {
        byte[] key = random(16);
        byte[] iv = random(12);
        for (String p : new String[]{provider, "BC"})
        {
            Mac m = gmac(p, key, iv);
            m.update(random(20));
            m.reset();
            refusedSpent(m, p);
        }
    }

    private static void reuseRefused(Mac m, byte[] key, byte[] iv, String what)
    {
        InvalidAlgorithmParameterException ex = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv)), what);
        if (!"BC".equals(m.getProvider().getName()))
        {
            Assertions.assertEquals(NONCE_REUSED, ex.getMessage(), what);
        }
    }

    /**
     * Init repeating the previous key and nonce is refused, with or without a doFinal first, and again after a
     * refused one, as BouncyCastle refuses it.
     */
    public static void gmacRefusesTheSameKeyAndNonce(String provider) throws Exception
    {
        byte[] key = random(32);
        byte[] iv = random(12);
        for (String p : new String[]{provider, "BC"})
        {
            Mac afterFinal = gmac(p, key, iv);
            afterFinal.doFinal(random(5));
            reuseRefused(afterFinal, key, iv, p + " after doFinal");
            reuseRefused(afterFinal, key, iv, p + " after a refused re-init");

            Mac noFinal = gmac(p, key, iv);
            noFinal.update(random(5));
            reuseRefused(noFinal, key, iv, p + " without doFinal");
        }
    }

    /** A refused re-init leaves the previous stream running: its tag equals a fresh instance's over both parts. */
    public static void gmacKeepsThePreviousStreamAfterARefusedReinit(String provider) throws Exception
    {
        byte[] key = random(16);
        byte[] iv = random(12);
        byte[] a = random(23);
        byte[] b = random(41);
        byte[][] tags = new byte[2][];
        String[] providers = {provider, "BC"};
        for (int i = 0; i < 2; i++)
        {
            Mac m = gmac(providers[i], key, iv);
            m.update(a);
            reuseRefused(m, key, iv, providers[i]);
            m.update(b);
            tags[i] = m.doFinal();
        }
        Mac fresh = gmac(provider, key, iv);
        fresh.update(a);
        fresh.update(b);
        Assertions.assertArrayEquals(fresh.doFinal(), tags[0], "against a fresh instance");
        Assertions.assertArrayEquals(tags[1], tags[0], "against BouncyCastle");
    }

    private static byte[] reinitTag(String provider, byte[] key, byte[] iv, byte[] msg) throws Exception
    {
        Mac fresh = gmac(provider, key, iv);
        return fresh.doFinal(msg);
    }

    /** Nonces A, B, A under one key are accepted, as BouncyCastle compares only the previous init. */
    public static void gmacAcceptsABANonces(String provider) throws Exception
    {
        byte[] key = random(16);
        byte[] ivA = random(12);
        byte[] ivB = random(12);
        byte[] msg = random(30);
        for (String p : new String[]{provider, "BC"})
        {
            Mac m = gmac(p, key, ivA);
            m.doFinal(random(3));
            m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(ivB));
            m.doFinal(random(3));
            m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(ivA));
            Assertions.assertArrayEquals(reinitTag(provider, key, ivA, msg), m.doFinal(msg), p);
        }
    }

    /** A refused bad-key init drops the previous key and nonce, so the same nonce is then accepted, as on BC. */
    public static void gmacAcceptsTheSameNonceAfterARefusedBadKeyInit(String provider) throws Exception
    {
        byte[] key = random(16);
        byte[] iv = random(12);
        byte[] msg = random(30);
        for (String p : new String[]{provider, "BC"})
        {
            Mac m = gmac(p, key, iv);
            m.doFinal(random(3));
            Assertions.assertThrows(Exception.class,
                    () -> m.init(new SecretKeySpec(new byte[15], "AES"), new IvParameterSpec(iv)), p + " bad key");
            m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            Assertions.assertArrayEquals(reinitTag(provider, key, iv, msg), m.doFinal(msg), p);
        }
    }

    /** A new nonce, or a new key, after doFinal works and equals a fresh instance and BouncyCastle. */
    public static void gmacNewNonceOrNewKeyEqualsAFreshInstance(String provider) throws Exception
    {
        byte[] key = random(32);
        byte[] otherKey = random(32);
        byte[] iv = random(12);
        byte[] otherIv = random(12);
        byte[] msg = random(50);
        for (String p : new String[]{provider, "BC"})
        {
            Mac m = gmac(p, key, iv);
            m.doFinal(random(7));
            m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(otherIv));
            Assertions.assertArrayEquals(reinitTag(provider, key, otherIv, msg), m.doFinal(msg), p + " new nonce");
            m.init(new SecretKeySpec(otherKey, "AES"), new IvParameterSpec(otherIv));
            Assertions.assertArrayEquals(reinitTag(provider, otherKey, otherIv, msg), m.doFinal(msg),
                    p + " new key");
        }
        Assertions.assertArrayEquals(reinitTag("BC", key, iv, msg), reinitTag(provider, key, iv, msg),
                "the providers agree on the GMAC itself");
    }

    /** Dispose through the other family frees nothing; each context is freed once, by its own dispose. */
    public static void wrongKindDisposeFreesNothing(MacServiceNI mac, MDServiceNI md, OperationsTestNI ops)
    {
        long macRef = hmac(mac);
        long mdRef = md(md);
        ops.ledgerReset();
        mac.ni_dispose(mdRef);
        md.ni_dispose(macRef);
        Assertions.assertEquals(0, ops.ledgerDestroyed(OperationsTestNI.LedgerType.MAC_CTX), "MAC_CTX");
        Assertions.assertEquals(0, ops.ledgerDestroyed(OperationsTestNI.LedgerType.MD_CTX), "MD_CTX");
        mac.ni_dispose(macRef);
        md.ni_dispose(mdRef);
        Assertions.assertEquals(1, ops.ledgerDestroyed(OperationsTestNI.LedgerType.MAC_CTX), "MAC_CTX");
        Assertions.assertEquals(1, ops.ledgerDestroyed(OperationsTestNI.LedgerType.MD_CTX), "MD_CTX");
    }

    /**
     * On FFM an unusable err array fails before a context exists, for allocate and copy. On JNI the same input
     * aborts at the bridge assert, which no in-suite cell can observe.
     */
    public static void unusableErrArrayCreatesNoContext(MacServiceNI mac, OperationsTestNI ops)
    {
        long src = hmac(mac);
        try
        {
            ops.ledgerReset();
            Assertions.assertThrows(NullPointerException.class, () -> mac.ni_allocateMac("HMAC", "SHA-256", null));
            Assertions.assertThrows(ArrayIndexOutOfBoundsException.class,
                    () -> mac.ni_allocateMac("HMAC", "SHA-256", new int[0]));
            Assertions.assertThrows(NullPointerException.class, () -> mac.ni_copyMac(src, null));
            Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> mac.ni_copyMac(src, new int[0]));
            Assertions.assertEquals(0, ops.ledgerCreated(OperationsTestNI.LedgerType.MAC_CTX), "created");
        }
        finally
        {
            mac.ni_dispose(src);
        }
    }

    /** JNI copies the key through a cleansing context; FFM reads the Java array and copies nothing. */
    public static void keyCopiesAreCleansed(MacServiceNI mac, OperationsTestNI ops)
    {
        long ref = hmac(mac);
        try
        {
            ops.ledgerReset();
            Assertions.assertEquals(0, mac.ni_init(ref, random(32), null, null, 0));
            int expected = Loader.isFFM() ? 0 : 1;
            for (OperationsTestNI.LedgerType t : new OperationsTestNI.LedgerType[]{
                    OperationsTestNI.LedgerType.SECRET_BYTEARRAY, OperationsTestNI.LedgerType.SECRET_CLEANSE})
            {
                Assertions.assertEquals(expected, ops.ledgerCreated(t), t + " created");
                Assertions.assertEquals(expected, ops.ledgerDestroyed(t), t + " destroyed");
            }
        }
        finally
        {
            mac.ni_dispose(ref);
        }
    }

    /**
     * A re-init inside reset that fails returns its code and leaves the context uninitialised with nothing held:
     * a second reset, the length and doFinal refuse, and every secret copy made was cleansed. armInitSite sets the
     * flag that fails the init site.
     */
    public static void failedReinitInsideResetDropsEverything(MacServiceNI mac, OperationsTestNI ops,
                                                              Runnable armInitSite, int injectedCode)
    {
        long ref = hmac(mac);
        try
        {
            ops.ledgerReset();
            Assertions.assertEquals(0, mac.ni_init(ref, random(32), null, null, 0));
            armInitSite.run();
            Assertions.assertEquals(injectedCode, mac.ni_reset(ref), "reset with the init site failing");
            ops.resetFlags();
            int notInit = ErrorCode.JO_NOT_INITIALIZED.getCode();
            Assertions.assertEquals(notInit, mac.ni_reset(ref), "second reset");
            Assertions.assertEquals(notInit, mac.ni_getMacLength(ref), "length");
            Assertions.assertEquals(notInit, mac.ni_doFinal(ref, new byte[32], 0), "doFinal");
            for (OperationsTestNI.LedgerType t : new OperationsTestNI.LedgerType[]{
                    OperationsTestNI.LedgerType.SECRET_BYTEARRAY, OperationsTestNI.LedgerType.SECRET_CLEANSE})
            {
                Assertions.assertEquals(ops.ledgerCreated(t), ops.ledgerDestroyed(t), t + " balanced");
            }
            // A new init works.
            byte[] key = random(32);
            Assertions.assertEquals(0, mac.ni_init(ref, key, null, null, 0));
            byte[] tag = new byte[32];
            Assertions.assertEquals(32, mac.ni_doFinal(ref, tag, 0));
            Assertions.assertArrayEquals(hmacReference(key, new byte[0]), tag);
        }
        finally
        {
            ops.resetFlags();
            mac.ni_dispose(ref);
        }
    }

    /**
     * A failing copy site returns its code through the NI with no context made, and through Mac.clone() as
     * CloneNotSupportedException carrying it. armSite sets the flag.
     */
    public static void copyFailureSite(MacServiceNI mac, OperationsTestNI ops, Runnable armSite,
                                       int injectedCode, String provider) throws Exception
    {
        long ref = hmac(mac);
        Mac jce = Mac.getInstance("HmacSHA256", provider);
        jce.init(new SecretKeySpec(random(32), "HmacSHA256"));
        try
        {
            ops.ledgerReset();
            armSite.run();
            int[] err = new int[1];
            Assertions.assertEquals(0L, mac.ni_copyMac(ref, err), "copy handle");
            Assertions.assertEquals(injectedCode, err[0], "copy code");
            CloneNotSupportedException ex = Assertions.assertThrows(CloneNotSupportedException.class, jce::clone);
            Assertions.assertEquals("unable to clone mac", ex.getMessage());
            Assertions.assertEquals("unexpected error code JO_UNKNOWN: " + injectedCode, ex.getCause().getMessage());
            Assertions.assertEquals(0, ops.ledgerCreated(OperationsTestNI.LedgerType.MAC_CTX), "created");
        }
        finally
        {
            ops.resetFlags();
            mac.ni_dispose(ref);
        }
    }

    /** JNI only: a GMAC nonce the bridge cannot access is a typed refusal. The caller sets the flag. */
    public static void gmacIvAccessFailure(MacServiceNI mac)
    {
        long ref = mac(mac, "GMAC", "aes-gcm");
        try
        {
            IllegalStateException ex = Assertions.assertThrows(IllegalStateException.class,
                    () -> mac.engineInit(ref, random(16), random(12), null, 0));
            Assertions.assertEquals("native layer was unable to access iv", ex.getMessage());
        }
        finally
        {
            mac.ni_dispose(ref);
        }
    }
}
