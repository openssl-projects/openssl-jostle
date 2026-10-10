/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.jcajce.provider.OverflowException;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

import javax.crypto.Cipher;

/**
 * Operations-test fault injection at the FIPS block-cipher NI surface. The
 * fault sites live in the shared interface/fips/util/block_cipher_ctx.c, re-included
 * into the FIPS library, so these fire identically when driven through
 * {@link FIPSNISelector#BlockCipherNI}. Mirrors {@code BlockCipherOpsTest}.
 *
 * <p>Every OPS-injected {@code JO_OPENSSL_ERROR} short-circuits before any real
 * OpenSSL call, so the error queue is empty and {@code baseErrorHandler} formats
 * the message as {@code "OpenSSL Error: null"}; pinning it catches a silent
 * re-map of the code to a different error arm.
 *
 * <p>FIPS divergence from the base: the two AES-OCB tests are omitted - OCB is
 * not FIPS-approved (the module won't fetch it, so the OPS site is unreachable).
 * All remaining tests use AES-CBC / AES-GCM, both approved.
 *
 * <p>Requires a JOSTLE_OPS_TEST build of the FIPS library: gated on
 * {@code TEST_FIPS_LIB} and per-test on {@code opsTestAvailable()}.
 */
public class FIPSBlockCipherOpsTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final BlockCipherNI blockCipherNI = FIPSNISelector.BlockCipherNI;
    private final OperationsTestNI operationsTestNI = FIPSNISelector.OperationsTestNI;

    @BeforeEach
    public void beforeEach() throws Exception
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    private static byte[] sequentialKey(int len)
    {
        byte[] k = new byte[len];
        for (int i = 0; i < len; i++)
        {
            k[i] = (byte) i;
        }
        return k;
    }

    private static byte[] sequentialIv(int len)
    {
        byte[] iv = new byte[len];
        for (int i = 0; i < len; i++)
        {
            iv[i] = (byte) (i + 100);
        }
        return iv;
    }

    @Test
    public void testFinalAutoResetFailureMakesCipherUnusable() throws Exception
    {
        // Drive block_cipher_ctx_final's auto-reset into failure via
        // OPS_FAILED_INIT_1; the ctx must poison and refuse subsequent ops.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                key[i] = (byte) i;
                iv[i] = (byte) (i + 16);
            }
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, iv, 0));

            byte[] in = new byte[16];
            byte[] out = new byte[32];
            blockCipherNI.update(ref, out, 0, in, 0, in.length);

            // Exercises interface/fips/util/block_cipher_ctx.c:1529
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            try
            {
                blockCipherNI.doFinal(ref, out, 0);
                Assertions.fail("expected reset failure to surface");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }

            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, out, 0, in, 0, in.length);
                Assertions.fail("expected cipher poisoned on update after reset failure");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }

            try
            {
                blockCipherNI.doFinal(ref, out, 0);
                Assertions.fail("expected cipher poisoned on doFinal after reset failure");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            if (operationsTestNI.opsTestAvailable())
            {
                operationsTestNI.resetFlags();
            }
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testCipherFetchFailure() throws Exception
    {
        // OPS_FAILED_CREATE_1 forces the EVP_CIPHER_fetch NULL-check branch.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            // Exercises interface/fips/util/block_cipher_ctx.c:1431
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);
            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected fetch failure to surface as OpenSSLException");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            // init failure leaves the ctx un-poisoned; retry must succeed.
            operationsTestNI.resetFlags();
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmSetIvLenFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_1 forces the GCM SET_IVLEN ctrl to look failed.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            // Exercises interface/fips/util/block_cipher_ctx.c:1511
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected SET_IVLEN failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testUpdateAADFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_2 forces _updateAAD's EVP_*Update to look failed.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
            // Exercises interface/fips/util/block_cipher_ctx.c:1715
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            try
            {
                blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
                Assertions.fail("expected updateAAD failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testUpdateFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_3 forces _update's EVP_*Update to look failed.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
            // Exercises interface/fips/util/block_cipher_ctx.c:1957
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected update failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testEncryptFinalFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_4 forces EVP_EncryptFinal_ex to look failed - poisons.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
            blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
            // Exercises interface/fips/util/block_cipher_ctx.c:2436
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected final failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned after EncryptFinal failure");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmGetTagFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_5 forces GCM GET_TAG to look failed - poisons.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
            blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);
            // Exercises interface/fips/util/block_cipher_ctx.c:2454
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);
            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected GET_TAG failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned after GET_TAG failure");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmSetTagInFinalFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_6 forces GCM SET_TAG inside _final to look failed - poisons.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
            byte[] ct = new byte[32];
            blockCipherNI.update(ref, new byte[32], 0, ct, 0, ct.length);
            // Exercises interface/fips/util/block_cipher_ctx.c:2480
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);
            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected SET_TAG failure in final");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned after SET_TAG failure");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmDecryptUpdateFailure_tagBufferPath() throws Exception
    {
        // GCM DECRYPT _update tag-buffer branch; OPS_OPENSSL_ERROR_3 fails the
        // EVP call - poisons (fill phase already mutated tag_index/buffer).
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
            // Exercises interface/fips/util/block_cipher_ctx.c:1957
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[32], 0, 32);
                Assertions.fail("expected GCM tag-buffer DecryptUpdate failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmDecryptUpdateFailure_tagRotatePath() throws Exception
    {
        // GCM DECRYPT tag-rotate "else if" branch; OPS_OPENSSL_ERROR_3 fails it.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
            blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);
            // Exercises interface/fips/util/block_cipher_ctx.c:1957
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            try
            {
                blockCipherNI.update(ref, new byte[16], 0, new byte[4], 0, 4);
                Assertions.fail("expected tag-rotate DecryptUpdate failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testNonGcmDecryptUpdateFailure() throws Exception
    {
        // Non-GCM DECRYPT simple-else branch; OPS_OPENSSL_ERROR_3 fails it.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
            // Exercises interface/fips/util/block_cipher_ctx.c:1957
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected CBC DecryptUpdate failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testUpdateAADFailure_decrypt() throws Exception
    {
        // DECRYPT-branch updateAAD failure (OPS_OPENSSL_ERROR_2) - poisons.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
            // Exercises interface/fips/util/block_cipher_ctx.c:1715
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            try
            {
                blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
                Assertions.fail("expected DECRYPT updateAAD failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            try
            {
                blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
                Assertions.fail("expected cipher poisoned");
            }
            catch (IllegalStateException ex)
            {
                Assertions.assertTrue(ex.getMessage().contains("poisoned"));
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmEncryptCipherOnlyInitFail() throws Exception
    {
        // OPS_FAILED_INIT_2 fails the GCM first-step (cipher-only) init; retry OK.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            // Exercises interface/fips/util/block_cipher_ctx.c:1507
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);
            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM cipher-only init failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmDecryptCipherOnlyInitFail() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            // Exercises interface/fips/util/block_cipher_ctx.c:1507
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);
            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM decrypt cipher-only init failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmEncryptKeyIvInitFail() throws Exception
    {
        // OPS_FAILED_INIT_1 in GCM ENCRYPT hits the third-step (key+iv) init.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            // Exercises interface/fips/util/block_cipher_ctx.c:1529
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM key+iv init failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmDecryptSetIvLenFail() throws Exception
    {
        // DECRYPT counterpart of testGcmSetIvLenFailure.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0);
            // Exercises interface/fips/util/block_cipher_ctx.c:1511
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected DECRYPT GCM SET_IVLEN failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGcmDecryptKeyIvInitFail() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0);
            // Exercises interface/fips/util/block_cipher_ctx.c:1529
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM decrypt key+iv init failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testNonGcmDecryptInitFail() throws Exception
    {
        // CBC/DECRYPT init branch (OPS_FAILED_INIT_1).
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            // Exercises interface/fips/util/block_cipher_ctx.c:1529
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);
            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected CBC decrypt init failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testSetPaddingFailure() throws Exception
    {
        // OPS_OPENSSL_ERROR_7 forces EVP_CIPHER_CTX_set_padding to look failed.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            // Exercises interface/fips/util/block_cipher_ctx.c:1594
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);
            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected set_padding failure to surface");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGetUpdateSize_inputOverflow() throws Exception
    {
        // OPS_INT32_OVERFLOW_1 forces the input-side len > INT32_MAX gate.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, PADDED
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
            // Exercises interface/fips/util/block_cipher_ctx.c:1693
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            try
            {
                blockCipherNI.getUpdateSize(ref, 16);
                Assertions.fail("OPS_INT32_OVERFLOW_1 must trip the input-side overflow gate");
            }
            catch (OverflowException ex)
            {
                Assertions.assertEquals("output too long int32", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            Assertions.assertEquals(16, blockCipherNI.getUpdateSize(ref, 16));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testGetUpdateSize_outputOverflow() throws Exception
    {
        // OPS_INT32_OVERFLOW_2 forces the post-computation result > INT32_MAX gate.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 1); // AES128, CBC, PADDED
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
            // Exercises interface/fips/util/block_cipher_ctx.c:1808
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_2);
            try
            {
                blockCipherNI.getUpdateSize(ref, 16);
                Assertions.fail("OPS_INT32_OVERFLOW_2 must trip the output-side overflow gate");
            }
            catch (OverflowException ex)
            {
                Assertions.assertEquals("output too long int32", ex.getMessage());
            }
            operationsTestNI.resetFlags();
            Assertions.assertEquals(16, blockCipherNI.getUpdateSize(ref, 16));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    private static void expectFailure(java.util.concurrent.Callable<Object> call,
                                      Class<? extends Exception> type, String message)
    {
        Exception ex = Assertions.assertThrows(Exception.class, call::call);
        Assertions.assertEquals(type, ex.getClass());
        Assertions.assertEquals(message, ex.getMessage());
    }

    private long initedGcm() throws Exception
    {
        long ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
        blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
        return ref;
    }

    @Test
    public void testXts_appendAllocationFailure() throws Exception
    {
        // The XTS accumulation buffer grows by malloc + copy; an allocation
        // failure there is unreachable in any real configuration, so OPS is
        // the only way to exercise it. The first update sizes the buffer, so
        // the flag is set before a SECOND, larger update forces the growth.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 11, 0); // AES128, XTS, NO_PADDING
            byte[] key = new byte[32];
            for (int i = 0; i < 16; i++)
            {
                key[i] = 0x11;
            }
            for (int i = 16; i < 32; i++)
            {
                key[i] = 0x22;
            }
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, new byte[16], 0));

            // Exercises interface/fips/util/block_cipher_ctx.c:270
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_10);

            try
            {
                blockCipherNI.update(ref, new byte[1024], 0, new byte[1024], 0, 1024);
                Assertions.fail("expected the XTS buffer allocation failure to surface");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testXts_finalEvpFailure() throws Exception
    {
        // The single EVP_{Encrypt,Decrypt}Update that consumes the accumulated
        // XTS data unit at final. Real OpenSSL only fails it for inputs the
        // layers above already reject, so OPS is the only route.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 11, 0); // AES128, XTS, NO_PADDING
            byte[] key = new byte[32];
            for (int i = 0; i < 16; i++)
            {
                key[i] = 0x11;
            }
            for (int i = 16; i < 32; i++)
            {
                key[i] = 0x22;
            }
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, key, new byte[16], 0));
            Assertions.assertEquals(0, blockCipherNI.update(ref, new byte[32], 0, new byte[32], 0, 32));

            // Exercises interface/fips/util/block_cipher_ctx.c:1566
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_8);

            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected the XTS final EVP failure to surface");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testCts_ctsModeNotSettable_refusedTyped() throws Exception
    {
        // The capability probe: EVP_CIPHER_CTX_set_params SILENTLY IGNORES an
        // unknown parameter and still returns 1, so without the settable-list
        // check the CS3 pin would be a no-op against a provider that does not
        // implement cts_mode - and the operation would emit OpenSSL's CS1
        // default under a CS3 name. Every supported environment lists it as
        // settable, so injection is the only way to reach this branch.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(
                    org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher.AES128.ordinal(),
                    org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode.CTS.ordinal(), 0);
            // Exercises interface/fips/util/block_cipher_ctx.c:1636
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_2);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected the cts_mode capability refusal");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals(ProviderCapabilityException.class, ex.getClass(),
                        "an absent cts_mode must be a capability refusal, not a generic error");
                Assertions.assertEquals(
                        "CBC-CTS requires an explicit cts_mode, which the loaded provider does not support",
                        ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testCts_ctsModeSetFailure() throws Exception
    {
        // The set itself failing (as opposed to the parameter being absent).
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(
                    org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher.AES128.ordinal(),
                    org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode.CTS.ordinal(), 0);
            // Exercises interface/fips/util/block_cipher_ctx.c:1646
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_SET_1);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected the cts_mode set failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals(OpenSSLException.class, ex.getClass(),
                        "a failed set is a generic OpenSSL error, not the capability refusal");
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void testAccumulator_growFailure() throws Exception
    {
        // The accumulator's grow path. BUF_MEM_grow_clean reallocates via
        // OPENSSL_clear_realloc so the previous plaintext copy is cleansed;
        // this drives the failure return, which no real configuration reaches.
        // Uses CTS, but the buffer is shared with XTS - mode_accumulates picks
        // it, so either mode exercises the same code.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(
                    org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher.AES128.ordinal(),
                    org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode.CTS.ordinal(), 0);
            Assertions.assertEquals(0,
                    blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));

            // Exercises interface/fips/util/block_cipher_ctx.c:295
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_11);

            try
            {
                blockCipherNI.update(ref, new byte[64], 0, new byte[32], 0, 32);
                Assertions.fail("expected the accumulator grow failure");
            }
            catch (OpenSSLException ex)
            {
                Assertions.assertEquals("OpenSSL Error: null", ex.getMessage());
            }
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniInit_keyAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = blockCipherNI.makeInstance(8, 1, 0);
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:56
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            expectFailure(() -> blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0),
                    IllegalStateException.class, "native layer was unable to access key");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniInit_ivAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = blockCipherNI.makeInstance(8, 1, 0);
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:61
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            expectFailure(() -> blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0),
                    IllegalStateException.class, "native layer was unable to access iv");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniUpdateAAD_inputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = initedGcm();
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:148
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            expectFailure(() -> blockCipherNI.updateAAD(ref, new byte[16], 0, 16),
                    AccessException.class, "unable to access input array");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniUpdate_inputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = initedGcm();
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:238
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            expectFailure(() -> blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16),
                    AccessException.class, "unable to access input array");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniUpdate_outputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = initedGcm();
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:243
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            expectFailure(() -> blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16),
                    AccessException.class, "unable to access output array");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniDoFinal_outputRangeFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = initedGcm();
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:294
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            expectFailure(() -> blockCipherNI.doFinal(ref, new byte[32], 0),
                    IllegalArgumentException.class, "output offset + length is out of range");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

    @Test
    public void jniDoFinal_outputAccessFailure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");
        Assumptions.assumeFalse(Loader.isFFM(), "JNI access sites");
        long ref = initedGcm();
        try
        {
            // Exercises interface/fips/jni/block_cipher_ni_jni.c:299
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            expectFailure(() -> blockCipherNI.doFinal(ref, new byte[32], 0),
                    AccessException.class, "unable to access output array");
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }
}
