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

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;
import org.openssl.jostle.util.ops.OperationsTestNI;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * CCM cells shared by the base and FIPS tests, each taking the NI or the provider it drives.
 */
public final class CCMCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private CCMCells()
    {
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static long ctx(CCMCipherNI ni)
    {
        int[] err = new int[1];
        long ref = ni.ni_makeInstance(CCMCipherNI.AES128, err);
        Assertions.assertEquals(0, err[0], "ni_makeInstance(AES128)");
        Assertions.assertNotEquals(0L, ref);
        return ref;
    }

    private static byte[] encrypt(CCMCipherNI ni, byte[] key, byte[] nonce, int tag, byte[] aad, byte[] pt)
    {
        long ref = ctx(ni);
        try
        {
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, key, nonce, tag));
            byte[] out = new byte[pt.length + tag];
            Assertions.assertEquals(out.length,
                    ni.ni_doFinal(ref, aad, aad == null ? 0 : aad.length, pt, 0, pt.length, out, 0));
            return out;
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    /**
     * A block cipher handle is refused at every CCM entry and a CCM handle at every block cipher entry, with
     * the wrong-kind code; dispose through the wrong family frees nothing, so both stay usable.
     */
    public static void wrongKindRefusedBothWays(CCMCipherNI ccm, BlockCipherNI bc)
    {
        long ccmRef = ctx(ccm);
        long bcRef = bc.makeInstance(OSSLCipher.AES128.ordinal(), OSSLMode.CBC.ordinal(), 0);
        try
        {
            int ccmWrong = ErrorCode.JO_CCM_CTX_WRONG_KIND.getCode();
            byte[] buf = new byte[32];
            Assertions.assertEquals(ccmWrong, ccm.ni_init(bcRef, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8),
                    "CCM init");
            Assertions.assertEquals(ccmWrong, ccm.ni_doFinal(bcRef, null, 0, random(16), 0, 16, buf, 0),
                    "CCM doFinal");
            Assertions.assertEquals(ccmWrong, ccm.ni_getOutputSize(bcRef, CCMCipherNI.OP_ENCRYPT, 16),
                    "CCM getOutputSize");
            IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ccm.getOutputSize(bcRef, CCMCipherNI.OP_ENCRYPT, 16));
            Assertions.assertEquals("handle is not a CCM context", ex.getMessage());

            int bcWrong = ErrorCode.JO_BLOCK_CIPHER_CTX_WRONG_KIND.getCode();
            Assertions.assertEquals(bcWrong, bc.ni_init(ccmRef, Cipher.ENCRYPT_MODE, random(16), random(16), 0),
                    "block cipher init");
            Assertions.assertEquals(bcWrong, bc.ni_updateAAD(ccmRef, buf, 0, 16), "block cipher updateAAD");
            Assertions.assertEquals(bcWrong, bc.ni_update(ccmRef, buf, 0, random(16), 0, 16), "block cipher update");
            Assertions.assertEquals(bcWrong, bc.ni_doFinal(ccmRef, buf, 0), "block cipher doFinal");
            Assertions.assertEquals(bcWrong, bc.ni_getFinalSize(ccmRef, 16), "block cipher getFinalSize");
            Assertions.assertEquals(bcWrong, bc.ni_getUpdateSize(ccmRef, 16), "block cipher getUpdateSize");

            ccm.ni_dispose(bcRef);
            bc.ni_dispose(ccmRef);

            // Both still work.
            Assertions.assertEquals(0, bc.ni_init(bcRef, Cipher.ENCRYPT_MODE, random(16), random(16), 0));
            Assertions.assertEquals(16, bc.ni_update(bcRef, buf, 0, random(16), 0, 16));
            Assertions.assertEquals(0, ccm.ni_init(ccmRef, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8));
            Assertions.assertEquals(24, ccm.ni_doFinal(ccmRef, null, 0, random(16), 0, 16, buf, 0));
        }
        finally
        {
            ccm.ni_dispose(ccmRef);
            bc.ni_dispose(bcRef);
        }
    }

    /** Re-init with a 7-byte nonce after a 13-byte one encrypts exactly as a fresh instance does. */
    public static void reinitWithAShorterNonceAgreesWithAFreshInstance(CCMCipherNI ni)
    {
        byte[] key = random(16);
        byte[] shortNonce = random(7);
        byte[] aad = random(9);
        byte[] pt = random(33);
        byte[] fresh = encrypt(ni, key, shortNonce, 8, aad, pt);

        long ref = ctx(ni);
        try
        {
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, random(16), random(13), 16));
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, key, shortNonce, 8));
            byte[] out = new byte[pt.length + 8];
            Assertions.assertEquals(out.length, ni.ni_doFinal(ref, aad, aad.length, pt, 0, pt.length, out, 0));
            Assertions.assertArrayEquals(fresh, out);
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    /**
     * A tampered tag clears the plaintext window and leaves every byte outside it as the caller left it; the
     * expected bytes are fixed, so JNI and FFM must produce the same buffer.
     */
    public static void failedTagClearsTheWindowOnly(CCMCipherNI ni)
    {
        for (int tag : new int[]{4, 16})
        {
            byte[] key = random(16);
            byte[] nonce = random(12);
            byte[] pt = random(32);
            byte[] ct = encrypt(ni, key, nonce, tag, null, pt);
            ct[ct.length - 1] ^= 1;

            int off = 5;
            byte[] out = random(off + pt.length + 7);
            byte[] expected = Arrays.clone(out);
            // Arrays is qualified where the JDK's is meant: jostle's of that name is imported
            java.util.Arrays.fill(expected, off, off + pt.length, (byte) 0);

            long ref = ctx(ni);
            try
            {
                Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_DECRYPT, key, nonce, tag));
                Assertions.assertEquals(ErrorCode.JO_INVALID_CIPHER_TEXT.getCode(),
                        ni.ni_doFinal(ref, null, 0, ct, 0, ct.length, out, off), "tag " + tag);
                Assertions.assertArrayEquals(expected, out, "tag " + tag);
            }
            finally
            {
                ni.ni_dispose(ref);
            }
        }
    }

    /** Encrypt then decrypt in place in one array at the same offset agrees with the separate-buffer result. */
    public static void inPlaceSameArray(CCMCipherNI ni)
    {
        byte[] key = random(16);
        byte[] nonce = random(12);
        byte[] aad = random(11);
        byte[] pt = random(40);
        int tag = 16;
        byte[] reference = encrypt(ni, key, nonce, tag, aad, pt);

        int off = 3;
        byte[] buf = random(off + pt.length + tag + 4);
        System.arraycopy(pt, 0, buf, off, pt.length);
        byte[] before = Arrays.clone(buf);

        long e = ctx(ni);
        long d = ctx(ni);
        try
        {
            Assertions.assertEquals(0, ni.ni_init(e, CCMCipherNI.OP_ENCRYPT, key, nonce, tag));
            Assertions.assertEquals(reference.length, ni.ni_doFinal(e, aad, aad.length, buf, off, pt.length, buf, off));
            Assertions.assertArrayEquals(reference, Arrays.copyOfRange(buf, off, off + reference.length));
            Assertions.assertArrayEquals(Arrays.copyOfRange(before, 0, off), Arrays.copyOfRange(buf, 0, off));
            Assertions.assertArrayEquals(Arrays.copyOfRange(before, off + reference.length, before.length),
                    Arrays.copyOfRange(buf, off + reference.length, buf.length));

            Assertions.assertEquals(0, ni.ni_init(d, CCMCipherNI.OP_DECRYPT, key, nonce, tag));
            Assertions.assertEquals(pt.length,
                    ni.ni_doFinal(d, aad, aad.length, buf, off, reference.length, buf, off));
            Assertions.assertArrayEquals(pt, Arrays.copyOfRange(buf, off, off + pt.length));
        }
        finally
        {
            ni.ni_dispose(e);
            ni.ni_dispose(d);
        }
    }

    /** A successful encrypt uses up the nonce, so the next encrypt needs a new init; decrypt is reusable. */
    public static void encryptIsSingleUseDecryptIsNot(CCMCipherNI ni)
    {
        byte[] key = random(16);
        byte[] nonce = random(12);
        byte[] pt = random(20);
        long ref = ctx(ni);
        try
        {
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, key, nonce, 8));
            byte[] ct = new byte[28];
            Assertions.assertEquals(28, ni.ni_doFinal(ref, null, 0, pt, 0, pt.length, ct, 0));
            Assertions.assertEquals(ErrorCode.JO_NOT_INITIALIZED.getCode(),
                    ni.ni_doFinal(ref, null, 0, pt, 0, pt.length, new byte[28], 0));
            IllegalStateException ex = Assertions.assertThrows(IllegalStateException.class,
                    () -> ni.doFinal(ref, null, 0, pt, 0, pt.length, new byte[28], 0));
            Assertions.assertEquals("not initialized", ex.getMessage());

            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_DECRYPT, key, nonce, 8));
            for (int i = 0; i < 2; i++)
            {
                byte[] back = new byte[20];
                Assertions.assertEquals(20, ni.ni_doFinal(ref, null, 0, ct, 0, ct.length, back, 0), "decrypt " + i);
                Assertions.assertArrayEquals(pt, back, "decrypt " + i);
            }
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    /** Tag 2 and 18, key 0, 15 and 33, getOutputSize op_mode 0 and 3, and an output one byte short. */
    public static void boundaryRefusals(CCMCipherNI ni)
    {
        long ref = ctx(ni);
        try
        {
            for (int tag : new int[]{2, 18})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, random(16), random(12), tag), "tag " + tag);
            }
            for (int keyLen : new int[]{0, 15, 33})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_KEY_LEN.getCode(),
                        ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, random(keyLen), random(12), 8), "key " + keyLen);
            }
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8));
            for (int opMode : new int[]{0, 3})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_OP_MODE.getCode(),
                        ni.ni_getOutputSize(ref, opMode, 16), "op_mode " + opMode);
            }
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_SMALL.getCode(),
                    ni.ni_doFinal(ref, null, 0, random(16), 0, 16, new byte[16 + 8 - 1], 0));
            Assertions.assertEquals(24, ni.ni_doFinal(ref, null, 0, random(16), 0, 16, new byte[16 + 8], 0));
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    /**
     * NIST SP 800-38C Appendix C examples 1 to 3 (AES-128): encrypt gives the published ciphertext, decrypt
     * recovers the payload, and one changed ciphertext byte is refused.
     */
    public static void sp80038cExamples(String provider) throws Exception
    {
        String key = "404142434445464748494a4b4c4d4e4f";
        String[][] examples = {
                {"10111213141516", "0001020304050607", "20212223", "32", "7162015b4dac255d"},
                {"1011121314151617", "000102030405060708090a0b0c0d0e0f", "202122232425262728292a2b2c2d2e2f", "48",
                        "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd"},
                {"101112131415161718191a1b", "000102030405060708090a0b0c0d0e0f10111213",
                        "202122232425262728292a2b2c2d2e2f3031323334353637", "64",
                        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"}};
        SecretKeySpec k = new SecretKeySpec(Hex.decode(key), "AES");
        for (String[] ex : examples)
        {
            GCMParameterSpec spec = new GCMParameterSpec(Integer.parseInt(ex[3]), Hex.decode(ex[0]));
            byte[] aad = Hex.decode(ex[1]);
            byte[] pt = Hex.decode(ex[2]);
            byte[] expected = Hex.decode(ex[4]);

            Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", provider);
            enc.init(Cipher.ENCRYPT_MODE, k, spec);
            enc.updateAAD(aad);
            Assertions.assertArrayEquals(expected, enc.doFinal(pt), ex[0]);

            Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", provider);
            dec.init(Cipher.DECRYPT_MODE, k, spec);
            dec.updateAAD(aad);
            Assertions.assertArrayEquals(pt, dec.doFinal(expected), ex[0]);

            byte[] changed = Arrays.clone(expected);
            changed[0] ^= 1;
            dec.init(Cipher.DECRYPT_MODE, k, spec);
            dec.updateAAD(aad);
            Assertions.assertThrows(AEADBadTagException.class, () -> dec.doFinal(changed), ex[0]);
        }
    }

    /** A decrypt input shorter than the tag cannot carry one. */
    public static void decryptShorterThanTheTagIsABadTag(String provider) throws Exception
    {
        Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", provider);
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(random(16), "AES"), new GCMParameterSpec(64, random(12)));
        Assertions.assertThrows(AEADBadTagException.class, () -> dec.doFinal(random(7)));
    }

    /** JNI copies key and nonce through the cleansing contexts; FFM reads the Java arrays and copies nothing. */
    public static void keyAndNonceCopiesAreCleansed(CCMCipherNI ni, OperationsTestNI ops)
    {
        long ref = ctx(ni);
        try
        {
            ops.ledgerReset();
            Assertions.assertEquals(0, ni.ni_init(ref, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8));
            int expected = Loader.isFFM() ? 0 : 2;
            for (OperationsTestNI.LedgerType t : new OperationsTestNI.LedgerType[]{
                    OperationsTestNI.LedgerType.SECRET_BYTEARRAY, OperationsTestNI.LedgerType.SECRET_CLEANSE})
            {
                Assertions.assertEquals(expected, ops.ledgerCreated(t), t + " created");
                Assertions.assertEquals(expected, ops.ledgerDestroyed(t), t + " destroyed");
            }
        }
        finally
        {
            ni.ni_dispose(ref);
        }
    }

    /** Dispose through the other family frees nothing; each context is freed once, by its own dispose. */
    public static void wrongKindDisposeFreesNothing(CCMCipherNI ccm, BlockCipherNI bc, OperationsTestNI ops)
    {
        long ccmRef = ctx(ccm);
        long bcRef = bc.makeInstance(OSSLCipher.AES128.ordinal(), OSSLMode.CBC.ordinal(), 0);
        ops.ledgerReset();
        ccm.ni_dispose(bcRef);
        bc.ni_dispose(ccmRef);
        Assertions.assertEquals(0, ops.ledgerDestroyed(OperationsTestNI.LedgerType.CCM_CTX), "CCM_CTX");
        Assertions.assertEquals(0, ops.ledgerDestroyed(OperationsTestNI.LedgerType.BLOCK_CIPHER_CTX), "block cipher");
        ccm.ni_dispose(ccmRef);
        bc.ni_dispose(bcRef);
        Assertions.assertEquals(1, ops.ledgerDestroyed(OperationsTestNI.LedgerType.CCM_CTX), "CCM_CTX");
        Assertions.assertEquals(1, ops.ledgerDestroyed(OperationsTestNI.LedgerType.BLOCK_CIPHER_CTX), "block cipher");
    }

    /**
     * On FFM an unusable err array fails before a context exists. On JNI the same input aborts at the bridge
     * assert, which no in-suite cell can observe.
     */
    public static void unusableErrArrayCreatesNoContext(CCMCipherNI ni, OperationsTestNI ops)
    {
        ops.ledgerReset();
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> ni.ni_makeInstance(CCMCipherNI.AES128, new int[0]));
        Assertions.assertThrows(NullPointerException.class, () -> ni.ni_makeInstance(CCMCipherNI.AES128, null));
        Assertions.assertEquals(0, ops.ledgerCreated(OperationsTestNI.LedgerType.CCM_CTX), "created");
        Assertions.assertEquals(0, ops.ledgerDestroyed(OperationsTestNI.LedgerType.CCM_CTX), "destroyed");
    }
}
