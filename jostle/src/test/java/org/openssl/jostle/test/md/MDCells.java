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

package org.openssl.jostle.test.md;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.provider.cache.NativeLengthCache;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.ops.OperationsTestNI;

import javax.crypto.Cipher;
import java.security.SecureRandom;

/**
 * Digest cells shared by the base and FIPS tests, each taking the NIs it drives.
 */
public final class MDCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String SHA256 = "SHA2-256";

    private MDCells()
    {
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    /** SHA-256 from BouncyCastle's lightweight API, which shares no code with either library. */
    private static byte[] reference(byte[] msg)
    {
        SHA256Digest d = new SHA256Digest();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    private static long md(MDServiceNI ni)
    {
        int[] err = new int[1];
        long ref = ni.ni_allocateDigest(SHA256, 0, err);
        Assertions.assertEquals(0, err[0], "ni_allocateDigest(" + SHA256 + ")");
        Assertions.assertNotEquals(0L, ref);
        return ref;
    }

    private static long ccm(CCMCipherNI ni)
    {
        int[] err = new int[1];
        long ref = ni.ni_makeInstance(CCMCipherNI.AES128, err);
        Assertions.assertEquals(0, err[0], "ni_makeInstance(AES128)");
        Assertions.assertNotEquals(0L, ref);
        return ref;
    }

    private static long bc(BlockCipherNI ni)
    {
        return ni.makeInstance(OSSLCipher.AES128.ordinal(), OSSLMode.CBC.ordinal(), 0);
    }

    /** Every digest entry taking a handle refuses a foreign handle with the wrong-kind code. */
    private static void refusedByEveryDigestEntry(MDServiceNI md, long foreign, String what)
    {
        int wrong = ErrorCode.JO_MD_CTX_WRONG_KIND.getCode();
        int[] err = new int[1];
        Assertions.assertEquals(0L, md.ni_copyDigest(foreign, err), what + " copy handle");
        Assertions.assertEquals(wrong, err[0], what + " copy");
        Assertions.assertEquals(wrong, md.ni_updateByte(foreign, (byte) 1), what + " updateByte");
        Assertions.assertEquals(wrong, md.ni_updateBytes(foreign, new byte[4], 0, 4), what + " updateBytes");
        Assertions.assertEquals(wrong, md.ni_getDigestOutputLen(foreign), what + " getDigestOutputLen");
        Assertions.assertEquals(wrong, md.ni_digest(foreign, new byte[32], 0, 32), what + " digest");
        Assertions.assertEquals(wrong, md.ni_digest(foreign, null, 0, 0), what + " digest length query");
        Assertions.assertEquals(wrong, md.ni_reset(foreign), what + " reset");
        IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                () -> md.getDigestOutputLen(foreign));
        Assertions.assertEquals("handle is not a digest context", ex.getMessage(), what);
        md.ni_dispose(foreign);
    }

    /**
     * A live block cipher or CCM handle is refused at every digest entry, and a digest handle at the block cipher
     * and CCM entries; dispose through the wrong family frees nothing, so all three stay usable.
     */
    public static void wrongKindRefusedBothWays(MDServiceNI md, BlockCipherNI bc, CCMCipherNI ccm)
    {
        long mdRef = md(md);
        long bcRef = bc(bc);
        long ccmRef = ccm(ccm);
        try
        {
            refusedByEveryDigestEntry(md, bcRef, "block cipher handle");
            refusedByEveryDigestEntry(md, ccmRef, "CCM handle");

            byte[] buf = new byte[32];
            int bcWrong = ErrorCode.JO_BLOCK_CIPHER_CTX_WRONG_KIND.getCode();
            Assertions.assertEquals(bcWrong, bc.ni_init(mdRef, Cipher.ENCRYPT_MODE, random(16), random(16), 0),
                    "block cipher init");
            Assertions.assertEquals(bcWrong, bc.ni_update(mdRef, buf, 0, random(16), 0, 16), "block cipher update");
            Assertions.assertEquals(bcWrong, bc.ni_doFinal(mdRef, buf, 0), "block cipher doFinal");
            int ccmWrong = ErrorCode.JO_CCM_CTX_WRONG_KIND.getCode();
            Assertions.assertEquals(ccmWrong, ccm.ni_init(mdRef, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8),
                    "CCM init");
            Assertions.assertEquals(ccmWrong, ccm.ni_getOutputSize(mdRef, CCMCipherNI.OP_ENCRYPT, 16),
                    "CCM getOutputSize");
            bc.ni_dispose(mdRef);
            ccm.ni_dispose(mdRef);

            // All three still work.
            byte[] msg = random(45);
            Assertions.assertEquals(msg.length, md.ni_updateBytes(mdRef, msg, 0, msg.length));
            byte[] out = new byte[32];
            Assertions.assertEquals(32, md.ni_digest(mdRef, out, 0, 32));
            Assertions.assertArrayEquals(reference(msg), out);
            Assertions.assertEquals(0, bc.ni_init(bcRef, Cipher.ENCRYPT_MODE, random(16), random(16), 0));
            Assertions.assertEquals(16, bc.ni_update(bcRef, buf, 0, random(16), 0, 16));
            Assertions.assertEquals(0, ccm.ni_init(ccmRef, CCMCipherNI.OP_ENCRYPT, random(16), random(12), 8));
            Assertions.assertEquals(24, ccm.ni_doFinal(ccmRef, null, 0, random(16), 0, 16, buf, 0));
        }
        finally
        {
            md.ni_dispose(mdRef);
            bc.ni_dispose(bcRef);
            ccm.ni_dispose(ccmRef);
        }
    }

    /** A 0 handle is refused with the null-context code at every entry taking one, reset included. */
    public static void nullHandleRefusedEverywhere(MDServiceNI md)
    {
        int expected = ErrorCode.JO_MD_CTX_IS_NULL.getCode();
        int[] err = new int[1];
        Assertions.assertEquals(0L, md.ni_copyDigest(0L, err), "copy handle");
        Assertions.assertEquals(expected, err[0], "copy");
        Assertions.assertEquals(expected, md.ni_updateByte(0L, (byte) 1), "updateByte");
        // The handle is checked before the input and range checks.
        Assertions.assertEquals(expected, md.ni_updateBytes(0L, new byte[4], 0, 4), "updateBytes");
        Assertions.assertEquals(expected, md.ni_getDigestOutputLen(0L), "getDigestOutputLen");
        Assertions.assertEquals(expected, md.ni_digest(0L, new byte[32], 0, 32), "digest");
        Assertions.assertEquals(expected, md.ni_digest(0L, null, 0, 0), "digest length query");
        Assertions.assertEquals(expected, md.ni_reset(0L), "reset");

        Runnable[] typed = {
                () -> md.copyDigest(0L),
                () -> md.engineUpdate(0L, (byte) 1),
                () -> md.engineUpdate(0L, new byte[4], 0, 4),
                () -> md.getDigestOutputLen(0L),
                () -> md.digest(0L, new byte[32], 0, 32),
                () -> md.reset(0L)};
        for (Runnable r : typed)
        {
            IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class, r::run);
            Assertions.assertEquals("md context is null", ex.getMessage());
        }
        md.ni_dispose(0L);
    }

    /**
     * An empty name, a lone NUL and a name with an embedded NUL name no digest, on both bridges; the same name
     * without the NUL allocates.
     */
    public static void embeddedNulNameIsNotFound(MDServiceNI md)
    {
        int notFound = ErrorCode.JO_NAME_NOT_FOUND.getCode();
        for (String name : new String[]{SHA256 + "\0x", SHA256 + "\0", "\0", ""})
        {
            int[] err = new int[1];
            long ref = md.ni_allocateDigest(name, 0, err);
            if (ref != 0)
            {
                md.ni_dispose(ref);
            }
            Assertions.assertEquals(0L, ref, "handle for " + name.length() + " chars");
            Assertions.assertEquals(notFound, err[0], "code for " + name.length() + " chars");
            IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> md.allocateDigest(name, 0));
            Assertions.assertEquals("name not found", ex.getMessage());
        }
        long ref = md(md);
        md.ni_dispose(ref);
    }

    /** An XOF name throws from digestOutputLength as allocateDigest does, every time, and nothing is cached. */
    public static void digestOutputLengthThrowsOnAnXofName(MDServiceNI md)
    {
        Assertions.assertEquals(32, md.digestOutputLength(SHA256));
        for (String xof : new String[]{"SHAKE-128", "SHAKE-256"})
        {
            for (int i = 0; i < 2; i++)
            {
                IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> md.digestOutputLength(xof));
                Assertions.assertEquals("xof length inconsistent with algorithm", ex.getMessage(), xof);
            }
            Assertions.assertEquals(NativeLengthCache.UNKNOWN, md.lengthCache().get(xof), xof);
        }
    }

    /** A digest into an output longer than the digest writes the digest and leaves the rest as it was. */
    public static void outputLongerThanTheDigestKeepsTheTail(MDServiceNI md)
    {
        byte[] msg = random(77);
        byte[] out = random(40);
        byte[] before = Arrays.clone(out);
        long ref = md(md);
        try
        {
            Assertions.assertEquals(msg.length, md.ni_updateBytes(ref, msg, 0, msg.length));
            Assertions.assertEquals(32, md.ni_digest(ref, out, 0, out.length));
            Assertions.assertArrayEquals(reference(msg), Arrays.copyOfRange(out, 0, 32));
            Assertions.assertArrayEquals(Arrays.copyOfRange(before, 32, 40), Arrays.copyOfRange(out, 32, 40));
        }
        finally
        {
            md.ni_dispose(ref);
        }
    }

    /** After a digest, a second digest and an update both fail until reset; reset makes the context usable. */
    public static void digestOrUpdateAfterDigestWithoutResetFails(MDServiceNI md)
    {
        int openSslError = ErrorCode.JO_OPENSSL_ERROR.getCode();
        byte[] msg = random(19);
        long ref = md(md);
        try
        {
            Assertions.assertEquals(msg.length, md.ni_updateBytes(ref, msg, 0, msg.length));
            Assertions.assertEquals(32, md.ni_digest(ref, new byte[32], 0, 32));
            Assertions.assertEquals(openSslError, md.ni_digest(ref, new byte[32], 0, 32), "second digest");
            Assertions.assertEquals(openSslError, md.ni_updateByte(ref, (byte) 1), "updateByte after digest");
            Assertions.assertEquals(openSslError, md.ni_updateBytes(ref, msg, 0, msg.length),
                    "updateBytes after digest");
            OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                    () -> md.digest(ref, new byte[32], 0, 32));
            Assertions.assertTrue(ex.getMessage().startsWith("OpenSSL Error:"), ex.getMessage());

            Assertions.assertEquals(0, md.ni_reset(ref));
            Assertions.assertEquals(msg.length, md.ni_updateBytes(ref, msg, 0, msg.length));
            byte[] out = new byte[32];
            Assertions.assertEquals(32, md.ni_digest(ref, out, 0, 32));
            Assertions.assertArrayEquals(reference(msg), out);
        }
        finally
        {
            md.ni_dispose(ref);
        }
    }

    /** Reset discards absorbed input, so a digest straight after it is the empty-input value. */
    public static void resetThenDigestGivesTheEmptyInputValue(MDServiceNI md)
    {
        byte[] empty = reference(new byte[0]);
        long ref = md(md);
        try
        {
            byte[] msg = random(50);
            Assertions.assertEquals(msg.length, md.ni_updateBytes(ref, msg, 0, msg.length));
            Assertions.assertEquals(0, md.ni_reset(ref));
            byte[] out = new byte[32];
            Assertions.assertEquals(32, md.ni_digest(ref, out, 0, 32));
            Assertions.assertArrayEquals(empty, out, "reset after update");

            Assertions.assertEquals(0, md.ni_reset(ref));
            Assertions.assertEquals(32, md.ni_digest(ref, out, 0, 32));
            Assertions.assertArrayEquals(empty, out, "reset after digest");
            Assertions.assertFalse(Arrays.areEqual(empty, reference(msg)));
        }
        finally
        {
            md.ni_dispose(ref);
        }
    }

    /** Dispose through the other families frees nothing; each context is freed once, by its own dispose. */
    public static void wrongKindDisposeFreesNothing(MDServiceNI md, BlockCipherNI bc, CCMCipherNI ccm,
                                                    OperationsTestNI ops)
    {
        long mdRef = md(md);
        long bcRef = bc(bc);
        long ccmRef = ccm(ccm);
        ops.ledgerReset();
        md.ni_dispose(bcRef);
        md.ni_dispose(ccmRef);
        bc.ni_dispose(mdRef);
        ccm.ni_dispose(mdRef);
        OperationsTestNI.LedgerType[] types = {OperationsTestNI.LedgerType.MD_CTX,
                OperationsTestNI.LedgerType.BLOCK_CIPHER_CTX, OperationsTestNI.LedgerType.CCM_CTX};
        for (OperationsTestNI.LedgerType t : types)
        {
            Assertions.assertEquals(0, ops.ledgerDestroyed(t), t + " after wrong-family disposes");
        }
        md.ni_dispose(mdRef);
        bc.ni_dispose(bcRef);
        ccm.ni_dispose(ccmRef);
        for (OperationsTestNI.LedgerType t : types)
        {
            Assertions.assertEquals(1, ops.ledgerDestroyed(t), t + " after own disposes");
        }
    }
}
