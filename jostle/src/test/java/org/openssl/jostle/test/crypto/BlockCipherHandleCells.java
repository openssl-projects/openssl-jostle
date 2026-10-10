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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.spec.SpecNI;

import javax.crypto.Cipher;
import java.security.SecureRandom;

/**
 * Block cipher NI cells shared by the base and FIPS limit tests, each taking the NI it drives.
 */
public final class BlockCipherHandleCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private BlockCipherHandleCells()
    {
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Every entry that takes a handle answers the same code for it. */
    private static void assertEveryEntry(BlockCipherNI ni, long ref, int expected)
    {
        byte[] buf = new byte[32];
        Assertions.assertEquals(expected, ni.ni_init(ref, Cipher.ENCRYPT_MODE, random(16), random(16), 0), "init");
        Assertions.assertEquals(expected, ni.ni_updateAAD(ref, buf, 0, 16), "updateAAD");
        Assertions.assertEquals(expected, ni.ni_update(ref, buf, 0, random(16), 0, 16), "update");
        Assertions.assertEquals(expected, ni.ni_doFinal(ref, buf, 0), "doFinal");
        Assertions.assertEquals(expected, ni.ni_getFinalSize(ref, 16), "getFinalSize");
        Assertions.assertEquals(expected, ni.ni_getUpdateSize(ref, 16), "getUpdateSize");
    }

    /** JNI checked tag_len before the key; both bridges now refuse the key first. */
    public static void nullKeyRefusedBeforeTagLen(BlockCipherNI ni)
    {
        long ref = ni.makeInstance(OSSLCipher.AES128.ordinal(), OSSLMode.GCM.ordinal(), 0);
        try
        {
            Assertions.assertEquals(ErrorCode.JO_KEY_IS_NULL.getCode(),
                    ni.ni_init(ref, Cipher.ENCRYPT_MODE, null, random(12), -1));
            Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                    ni.ni_init(ref, Cipher.ENCRYPT_MODE, random(16), random(12), -1));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    public static void nullHandleRefusedAtEveryEntry(BlockCipherNI ni)
    {
        assertEveryEntry(ni, 0, ErrorCode.JO_BLOCK_CIPHER_CTX_IS_NULL.getCode());
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ni.init(0, Cipher.ENCRYPT_MODE, random(16), random(16), 0));
        Assertions.assertEquals("block cipher context is null", ex.getMessage());
        // Frees nothing and returns.
        ni.dispose(0);
    }

    /** A key spec handle passed as a block cipher handle is refused, and dispose leaves the spec intact. */
    public static void wrongKindRefusedAtEveryEntry(BlockCipherNI ni, SpecNI specNi)
    {
        long spec = specNi.allocate();
        try
        {
            Assertions.assertTrue(spec != 0);
            assertEveryEntry(ni, spec, ErrorCode.JO_BLOCK_CIPHER_CTX_WRONG_KIND.getCode());
            IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ni.getFinalSize(spec, 16));
            Assertions.assertEquals("handle is not a block cipher context", ex.getMessage());
            ni.dispose(spec);
            // Still a key spec: the refusal read only its kind.
            Assertions.assertEquals(ErrorCode.JO_BLOCK_CIPHER_CTX_WRONG_KIND.getCode(), ni.ni_getUpdateSize(spec, 16));
        }
        finally
        {
            specNi.dispose(spec);
        }
    }

    /** GCM and OCB refuse a tag below 4 bytes at init, and take 4 and 16. */
    public static void aeadTagFloor(BlockCipherNI ni, OSSLMode mode)
    {
        int ivLen = 12;
        long ref = ni.makeInstance(OSSLCipher.AES128.ordinal(), mode.ordinal(), 0);
        try
        {
            for (int tag : new int[]{0, 1, 3})
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                        ni.ni_init(ref, Cipher.ENCRYPT_MODE, random(16), random(ivLen), tag), mode + " tag " + tag);
                Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                        ni.ni_init(ref, Cipher.DECRYPT_MODE, random(16), random(ivLen), tag), mode + " tag " + tag);
            }
            IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ni.init(ref, Cipher.ENCRYPT_MODE, random(16), random(ivLen), 3));
            Assertions.assertEquals("invalid tag len", ex.getMessage());
            for (int tag : new int[]{4, 16})
            {
                Assertions.assertEquals(0, ni.ni_init(ref, Cipher.ENCRYPT_MODE, random(16), random(ivLen), tag),
                        mode + " tag " + tag);
                Assertions.assertEquals(0, ni.ni_init(ref, Cipher.DECRYPT_MODE, random(16), random(ivLen), tag),
                        mode + " tag " + tag);
            }
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * Every AES key wrap init the library can fetch passes the post-fetch guard, which expects the 8-byte semiblock
     * from a wrap fetch: a library that reported anything else would refuse here.
     */
    public static void wrapInitsPassTheSemiblockGuard(BlockCipherNI ni, boolean requireAll)
    {
        int driven = 0;
        for (OSSLCipher cipher : new OSSLCipher[]{OSSLCipher.AES128, OSSLCipher.AES192, OSSLCipher.AES256})
        {
            for (OSSLMode mode : new OSSLMode[]{OSSLMode.WRAP, OSSLMode.WRAP_PAD, OSSLMode.WRAP_INV})
            {
                if (!ni.cipherFetchable(cipher.ordinal(), mode.ordinal()))
                {
                    Assertions.assertFalse(requireAll, cipher + "/" + mode + " not fetchable");
                    continue;
                }
                int keyLen = cipher == OSSLCipher.AES128 ? 16 : (cipher == OSSLCipher.AES192 ? 24 : 32);
                long ref = ni.makeInstance(cipher.ordinal(), mode.ordinal(), 0);
                try
                {
                    Assertions.assertEquals(0, ni.ni_init(ref, Cipher.ENCRYPT_MODE, random(keyLen), null, 0),
                            cipher + "/" + mode + " encrypt");
                    Assertions.assertEquals(0, ni.ni_init(ref, Cipher.DECRYPT_MODE, random(keyLen), null, 0),
                            cipher + "/" + mode + " decrypt");
                    driven++;
                }
                finally
                {
                    ni.dispose(ref);
                }
            }
        }
        Assertions.assertTrue(driven > 0, "no AES key wrap was fetchable");
    }
}
