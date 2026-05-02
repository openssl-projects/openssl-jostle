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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

import javax.crypto.Cipher;
import java.security.Security;

public class BlockCipherOpsTest
{

    BlockCipherNI blockCipherNI = TestNISelector.getBlockCipher();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @BeforeEach
    public void beforeEach()
    {
        if (operationsTestNI.opsTestAvailable())
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void testFinalAutoResetFailureMakesCipherUnusable() throws Exception
    {
        // Drive block_cipher_ctx_final's auto-reset into failure via
        // OPS_FAILED_INIT_1 (forces EVP_*Init_ex to look failed). The ctx
        // is now in an undefined internal state, so we must:
        //   1. surface the reset failure on the same final call;
        //   2. refuse all subsequent ops on this handle (poison it);
        //   3. only destroy + create can recover.

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

            // Encrypt one block before triggering the failure so update has
            // exercised real work.
            byte[] in = new byte[16];
            byte[] out = new byte[32];
            blockCipherNI.update(ref, out, 0, in, 0, in.length);

            // Force the next EVP_*Init_ex inside _init to look failed.
            // The auto-reset inside doFinal calls _init, so this hits the
            // reset path specifically.
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);

            // doFinal: EVP_EncryptFinal_ex runs OK, but the auto-reset's
            // _init fails. Fix #3 propagates the reset error; the new
            // poison-on-reset wiring marks the ctx unusable.
            try
            {
                blockCipherNI.doFinal(ref, out, 0);
                Assertions.fail("expected reset failure to surface");
            }
            catch (OpenSSLException ex)
            {
                // JO_OPENSSL_ERROR from the failed init — surfaces as
                // OpenSSLException via baseErrorHandler.
            }

            // Clear the OPS flag so subsequent calls would normally succeed.
            // The poison flag must keep them refusing.
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

    private static byte[] sequentialKey(int len)
    {
        byte[] k = new byte[len];
        for (int i = 0; i < len; i++) k[i] = (byte) i;
        return k;
    }

    private static byte[] sequentialIv(int len)
    {
        byte[] iv = new byte[len];
        for (int i = 0; i < len; i++) iv[i] = (byte) (i + 100);
        return iv;
    }

    @Test
    public void testCipherFetchFailure() throws Exception
    {
        // OPS_FAILED_CREATE_1 forces the EVP_CIPHER_fetch NULL-check branch
        // to fire. _init returns JO_OPENSSL_ERROR; ctx->initialized stays 0.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_CREATE_1);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected fetch failure to surface as OpenSSLException");
            }
            catch (OpenSSLException ex)
            {
                // expected
            }

            // Reset; init failure should leave the ctx un-poisoned and the
            // user can retry init successfully.
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
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected SET_IVLEN failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            try
            {
                blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
                Assertions.fail("expected updateAAD failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected update failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // OPS_OPENSSL_ERROR_4 forces EVP_EncryptFinal_ex to look failed.
        // The ctx now poisons on this path (EVP_*Final_ex leaves the EVP
        // ctx in an undefined state; auto-reset is unsafe because it would
        // re-use the same key+iv — nonce reuse for GCM/CTR).
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));

            // Update one block so final has work to do.
            blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);

            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected final failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
            }

            // Clear flag — poison must outlast it.
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
        // OPS_OPENSSL_ERROR_5 forces GCM GET_TAG to look failed. EncryptFinal
        // already mutated the EVP ctx; tag retrieval failure now poisons
        // (auto-reset would re-use the GCM nonce).
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));

            blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_5);

            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected GET_TAG failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // OPS_OPENSSL_ERROR_6 forces GCM SET_TAG inside _final to look failed.
        // SET_TAG failure leaves the EVP ctx partially configured — poisons.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));

            // Feed enough bytes so the tag buffer fills.
            byte[] ct = new byte[32];
            blockCipherNI.update(ref, new byte[32], 0, ct, 0, ct.length);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_6);

            try
            {
                blockCipherNI.doFinal(ref, new byte[32], 0);
                Assertions.fail("expected SET_TAG failure in final");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // GCM DECRYPT _update with input >= 2*tag_len fills the tag buffer
        // and feeds it through EVP_DecryptUpdate (the "in_len >= tag_len"
        // branch). OPS_OPENSSL_ERROR_3 forces that EVP call to fail; the
        // ctx must be poisoned because the fill phase already mutated
        // tag_index / tag_buffer.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

            try
            {
                // 32 bytes: 16 fill the tag buffer, 16 trigger the in_len >= tag_len path.
                blockCipherNI.update(ref, new byte[32], 0, new byte[32], 0, 32);
                Assertions.fail("expected GCM tag-buffer DecryptUpdate failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // GCM DECRYPT tag-rotate path: first feed enough bytes to fill the
        // tag buffer exactly (no second-branch entry, no flag yet). Then
        // arm the OPS flag and feed a small input — the "else if (in_len > 0)"
        // branch fires, EVP_DecryptUpdate with the rotated tag_buffer fails.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));

            // Fill tag buffer with exactly tag_len bytes; in_len_post_fill = 0,
            // so neither inner branch fires and tag_index ends at tag_len.
            blockCipherNI.update(ref, new byte[16], 0, new byte[16], 0, 16);

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

            try
            {
                // 4 bytes < tag_len: drives the tag-rotate "else if" branch.
                blockCipherNI.update(ref, new byte[16], 0, new byte[4], 0, 4);
                Assertions.fail("expected tag-rotate DecryptUpdate failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // Non-GCM DECRYPT path uses the simple else branch (no tag buffer).
        // Distinct line from the GCM paths — needs its own coverage hit.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);

            try
            {
                blockCipherNI.update(ref, new byte[32], 0, new byte[16], 0, 16);
                Assertions.fail("expected CBC DecryptUpdate failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // Existing testUpdateAADFailure tests the ENCRYPT branch; this
        // covers the DECRYPT branch's poison + OPENSSL_ERROR return.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16));

            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);

            try
            {
                blockCipherNI.updateAAD(ref, new byte[16], 0, 16);
                Assertions.fail("expected DECRYPT updateAAD failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // GCM init is a three-step dance: cipher-only Init_ex → SET_IVLEN →
        // key+iv Init_ex. OPS_FAILED_INIT_2 forces the FIRST step (cipher-
        // only) to look failed. ctx->initialized stays 0; init can be retried.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM cipher-only init failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
            }

            // Recoverable: clearing the flag and retrying should succeed.
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
        // Mirror of the encrypt path: OPS_FAILED_INIT_2 with DECRYPT_MODE
        // exercises the GCM decrypt three-step's first init failure.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_2);

            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM decrypt cipher-only init failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // OPS_FAILED_INIT_1 in GCM ENCRYPT mode hits the third-step init
        // (key+iv); the cipher-only init and SET_IVLEN already succeeded.
        // The pre-existing testFinalAutoResetFailureMakesCipherUnusable
        // covers OPS_FAILED_INIT_1 only on the non-GCM single-call path —
        // this exercises the GCM-specific branch.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0); // AES128, GCM
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM key+iv init failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // Existing testGcmSetIvLenFailure covers ENCRYPT; this is the
        // DECRYPT counterpart — distinct call site in the C source.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected DECRYPT GCM SET_IVLEN failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // GCM DECRYPT third-step (key+iv) init failure.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 8, 0);
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);

            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(12), 16);
                Assertions.fail("expected GCM decrypt key+iv init failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // testFinalAutoResetFailureMakesCipherUnusable uses CBC/ENCRYPT;
        // this hits the parallel CBC/DECRYPT init branch.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_INIT_1);

            try
            {
                blockCipherNI.init(ref, Cipher.DECRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected CBC decrypt init failure");
            }
            catch (OpenSSLException ex)
            {
                // expected
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
        // OPS_OPENSSL_ERROR_7 forces EVP_CIPHER_CTX_set_padding to look failed
        // during CBC/ECB init. The fix surfaces it as JO_OPENSSL_ERROR rather
        // than silently leaving the ctx with whatever default OpenSSL applied.
        // ctx->initialized stays 0, so the user can retry init successfully.
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable(), "Ops Test only");

        long ref = 0;
        try
        {
            ref = blockCipherNI.makeInstance(8, 1, 0); // AES128, CBC, NO_PADDING
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_7);

            try
            {
                blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0);
                Assertions.fail("expected set_padding failure to surface");
            }
            catch (OpenSSLException ex)
            {
                // expected
            }

            // Clear flag; init failure should leave the ctx un-poisoned and
            // the user can retry init successfully.
            operationsTestNI.resetFlags();
            Assertions.assertEquals(0, blockCipherNI.init(ref, Cipher.ENCRYPT_MODE, sequentialKey(16), sequentialIv(16), 0));
        }
        finally
        {
            operationsTestNI.resetFlags();
            blockCipherNI.dispose(ref);
        }
    }

}
