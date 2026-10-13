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

package org.openssl.jostle.test.eddsa;

import org.junit.jupiter.api.*;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSL;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class EdDSAOpsTest
{
    EDServiceNI edDSAServiceNI = TestNISelector.getEdNi();
    SpecNI specNI = TestNISelector.getSpecNI();
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
    public void testEDDSAGenerateKeyPair_openSSLError() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long keyRef = 0;
        try
        {
            // Exercises interface/nonfips/util/edec.c:70
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);

            edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            //
            // Asserting the code path would actually return if there was an error.
            // There isn't an error so the msg is null
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);

        }
    }

    // -----------------------------------------------------------------
    // edec_generate_key — additional EVP failure points.
    //
    // The existing openSSLError test (above) exercises OPS_OPENSSL_ERROR_1
    // which forces the post-keygen spec->key == NULL trick. The three
    // tests below cover the actual EVP call failure paths that were
    // previously uninstrumented:
    //
    //   1. EVP_PKEY_CTX_new_from_name (ctx allocation) — slot _2, offset 1010
    //   2. EVP_PKEY_keygen_init                       — slot _3, offset 1011
    //   3. EVP_PKEY_keygen                            — slot _4, offset 1012
    //
    // Slots _2/_3/_4 are reused — they currently fire in edec_get_*_encoded
    // and edec_ctx_* paths, none of which are reachable during
    // edec_generate_key (which only calls EVP, not the other helpers).
    // -----------------------------------------------------------------

    @Test
    public void testEDDSAGenerateKeyPair_ctxNewFromName_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        try
        {
            // Exercises interface/nonfips/util/edec.c:52
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int[] err = new int[1];
            long ref = edDSAServiceNI.ni_generateKeyPair(
                    OSSLKeyType.ED25519.getKsType(), err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            // -2 + (-1010) = -1012.
            Assertions.assertEquals(-1012, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void testEDDSAGenerateKeyPair_keygenInit_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        try
        {
            // Exercises interface/nonfips/util/edec.c:58
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int[] err = new int[1];
            long ref = edDSAServiceNI.ni_generateKeyPair(
                    OSSLKeyType.ED25519.getKsType(), err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            // -2 + (-1011) = -1013.
            Assertions.assertEquals(-1013, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test
    public void testEDDSAGenerateKeyPair_evpKeygen_failure() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        try
        {
            // Exercises interface/nonfips/util/edec.c:64
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int[] err = new int[1];
            long ref = edDSAServiceNI.ni_generateKeyPair(
                    OSSLKeyType.ED25519.getKsType(), err, TestUtil.RNDSrc);
            Assertions.assertEquals(0L, ref);
            // -2 + (-1012) = -1014.
            Assertions.assertEquals(-1014, err[0]);
        }
        finally
        {
            operationsTestNI.resetFlags();
        }
    }

    @Test()
    public void EDDSAServiceJNI__initSign_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            // Exercises interface/nonfips/jni/ed_jni.c:327
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            edDSAServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void eddsa_initSign_nameAccessFails() throws Exception
    {
        // JNI-only: OPS_FAILED_ACCESS_2 short-circuits the GetStringUTFChars
        // name access in ni_initSign so the JO_UNABLE_TO_ACCESS_NAME path is
        // exercised without an impossible-to-provoke real failure. The FFM
        // bridge has no GetStringUTFChars equivalent.
        // JO_UNABLE_TO_ACCESS_NAME -> IllegalStateException("unable to access name").
        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;
        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);
            Assertions.assertTrue(keyRef > 0);

            // Exercises interface/nonfips/jni/ed_jni.c:308
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            edDSAServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0, TestUtil.RNDSrc);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unable to access name", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);
        }
    }

    @Test()
    public void EDDSAServiceJNI__initSign_createDigestCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            // Exercises interface/nonfips/util/edec.c:483
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = edDSAServiceNI.ni_initSign(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1002, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initSign_EVP_PKEY_sign_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            // Exercises interface/nonfips/util/edec.c:504
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = edDSAServiceNI.ni_initSign(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0, TestUtil.RNDSrc);
            Assertions.assertEquals(-1003, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI__initVerify_accessContextArray() throws Exception
    {

        Assumptions.assumeFalse(Loader.isFFM());
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            // Exercises interface/nonfips/jni/ed_jni.c:462
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);

            edDSAServiceNI.initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 1024);
            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access context array", e.getMessage());

        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initVerify_createDigestCTX() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            // Exercises interface/nonfips/util/edec.c:563
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            long code = edDSAServiceNI.ni_initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0);
            Assertions.assertEquals(-1005, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI__initVerify_EVP_PKEY_message_init() throws Exception
    {
        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);


            // Exercises interface/nonfips/util/edec.c:582
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            long code = edDSAServiceNI.ni_initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[1024], 0);
            Assertions.assertEquals(-1006, code); // OpenSSL error with offset
        }
        finally
        {
            operationsTestNI.resetFlags();
            specNI.dispose(keyRef);
            edDSAServiceNI.disposeSigner(eddsaRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_sign_outputRange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            // Exercises interface/nonfips/jni/ed_jni.c:392
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            edDSAServiceNI.sign(eddsaRef, new byte[1], 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access output array", e.getMessage());
        }
        finally
        {
            operationsTestNI.resetFlags();
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);
        }
    }

   // @Test()
    public void EDDSAServiceJNI_eddsa_sign_osslErrorGettingLen() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);

            // Exercises interface/nonfips/util/edec.c:676
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            OpenSSL.getOpenSSLErrors(); // Purge any errors
            long len = edDSAServiceNI.sign(eddsaRef, null, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_sign_osslErrorCalculatingSig() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0, TestUtil.RNDSrc);


            long len = edDSAServiceNI.sign(eddsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            // Exercises interface/nonfips/util/edec.c:700
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            edDSAServiceNI.sign(eddsaRef, sig, 0, TestUtil.RNDSrc);


            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertEquals("OpenSSL Error: null", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_sign_unexpectedSigLenChange() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initSign(eddsaRef, keyRef, "ED25519", null, 0, TestUtil.RNDSrc);

            long len = edDSAServiceNI.sign(eddsaRef, null, 0, TestUtil.RNDSrc);

            byte[] sig = new byte[(int) len];

            // Exercises interface/nonfips/util/edec.c:706
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            edDSAServiceNI.sign(eddsaRef, sig, 0, TestUtil.RNDSrc);

            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected sig length change", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    @Test()
    public void EDDSAServiceJNI_eddsa_verify_accessSigBytes() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            OpenSSL.getOpenSSLErrors(); // Purge any errors
            // Exercises interface/nonfips/jni/ed_jni.c:527
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            edDSAServiceNI.verify(eddsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (AccessException e)
        {
            Assertions.assertEquals("unable to access signature array", e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }


    @Test()
    public void EDDSAServiceJNI_eddsa_verify_osslError() throws Exception
    {

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());

        long eddsaRef = 0;
        long keyRef = 0;

        try
        {
            eddsaRef = edDSAServiceNI.allocateSigner();
            Assertions.assertTrue(eddsaRef > 0);
            keyRef = edDSAServiceNI.generateKeyPair(OSSLKeyType.ED25519.getKsType(), TestUtil.RNDSrc);

            Assertions.assertTrue(keyRef > 0);
            edDSAServiceNI.initVerify(eddsaRef, keyRef, "ED25519ctx", new byte[0], 0);

            // Exercises interface/nonfips/util/edec.c:755
            operationsTestNI.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            edDSAServiceNI.verify(eddsaRef, new byte[1], 1);

            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            // Real OpenSSL errors (e.g., the EVP_DigestVerify "provider signature failure"
            // raised here by the deliberately-too-short 1-byte signature) are preserved on
            // the error queue and surface through the JO_OPENSSL_ERROR path. The exact text
            // varies across OpenSSL versions; assert the prefix and the failing function.
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"),
                    "expected OpenSSL Error prefix, got: " + e.getMessage());
            Assertions.assertTrue(e.getMessage().contains("EVP_DigestVerify"),
                    "expected EVP_DigestVerify reference, got: " + e.getMessage());
        }
        finally
        {
            edDSAServiceNI.disposeSigner(eddsaRef);
            specNI.dispose(keyRef);

        }
    }

    // Cells for the fault sites below, one per site.

    private final EDServiceNI ed = edDSAServiceNI;
    private final OperationsTestNI ops = operationsTestNI;

    private static final RandSource RND = TestUtil.RNDSrc;
    private static final int ED25519 = OSSLKeyType.ED25519.getKsType();
    private static final String NAME = OSSLKeyType.ED25519.getTypeName();
    private static final int JO_OPENSSL_ERROR = ErrorCode.JO_OPENSSL_ERROR.getCode();
    private static final int JO_OUTPUT_SIZE_INT_OVERFLOW = ErrorCode.JO_OUTPUT_SIZE_INT_OVERFLOW.getCode();
    private static final int JO_OUTPUT_TOO_LONG_INT32 = ErrorCode.JO_OUTPUT_TOO_LONG_INT32.getCode();
    private static final int JO_OUTPUT_TOO_SMALL = ErrorCode.JO_OUTPUT_TOO_SMALL.getCode();
    private static final int JO_UNEXPECTED_SIG_LEN_CHANGE = ErrorCode.JO_UNEXPECTED_SIG_LEN_CHANGE.getCode();
    private static final int JO_FAILED_ACCESS_INPUT = ErrorCode.JO_FAILED_ACCESS_INPUT.getCode();
    private static final int JO_FAILED_ACCESS_OUTPUT = ErrorCode.JO_FAILED_ACCESS_OUTPUT.getCode();
    private static final int JO_FAILED_ACCESS_CONTEXT = ErrorCode.JO_FAILED_ACCESS_CONTEXT.getCode();
    private static final int JO_FAILED_ACCESS_SIG = ErrorCode.JO_FAILED_ACCESS_SIG.getCode();
    private static final int JO_UNABLE_TO_ACCESS_NAME = ErrorCode.JO_UNABLE_TO_ACCESS_NAME.getCode();

    /** The code a fault site with this offset returns. */
    private static int errorAt(int offset)
    {
        return JO_OPENSSL_ERROR - offset;
    }

    @Test
    public void site_getPublicKey_sizeQuery()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/util/edec.c:111
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_getPublicKey(keyRef, null));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_getPublicKey_fill()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/util/edec.c:128
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(errorAt(1000), ed.ni_getPublicKey(keyRef, new byte[32]));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_getPublicKey_overflow()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/util/edec.c:133
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(JO_OUTPUT_SIZE_INT_OVERFLOW, ed.ni_getPublicKey(keyRef, new byte[32]));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_getPrivateKey_sizeQuery()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/util/edec.c:161
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_getPrivateKey(keyRef, null));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_getPrivateKey_fill()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/util/edec.c:177
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            byte[] out = new byte[32];
            Assertions.assertEquals(errorAt(1000), ed.ni_getPrivateKey(keyRef, out));
            Assertions.assertArrayEquals(new byte[32], out);
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_getPrivateKey_overflow()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/util/edec.c:182
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(JO_OUTPUT_SIZE_INT_OVERFLOW, ed.ni_getPrivateKey(keyRef, new byte[32]));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_decodePrivateKey_nullKey()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/nonfips/util/edec.c:288
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_decode_privateKey(target, ED25519, privateBytes, 0, 32));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(target);
            specNI.dispose(src);
        }
    }

    @Test
    public void site_decodePublicKey_nullKey()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/nonfips/util/edec.c:365
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_decode_publicKey(target, ED25519, publicBytes, 0, 32));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(target);
            specNI.dispose(src);
        }
    }

    @Test
    public void site_allocateSigner_bio()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        try
        {
            // Exercises interface/nonfips/util/edec.c:394
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            Assertions.assertEquals(0L, ed.ni_allocateSigner(err));
            Assertions.assertEquals(JO_OPENSSL_ERROR, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void site_sign_overflow()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initSign(sigRef, keyRef, NAME, null, 0, RND);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/nonfips/util/edec.c:682
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_INT32_OVERFLOW_1);
            Assertions.assertEquals(JO_OUTPUT_TOO_LONG_INT32, ed.ni_sign(sigRef, null, 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_jni_decodePublicKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/nonfips/jni/ed_jni.c:114
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT,
                    ed.ni_decode_publicKey(target, ED25519, publicBytes, 0, 32));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(target);
            specNI.dispose(src);
        }
    }

    @Test
    public void site_jni_decodePrivateKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/nonfips/jni/ed_jni.c:173
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT,
                    ed.ni_decode_privateKey(target, ED25519, privateBytes, 0, 32));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(target);
            specNI.dispose(src);
        }
    }

    @Test
    public void site_jni_getPublicKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/jni/ed_jni.c:230
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, ed.ni_getPublicKey(keyRef, new byte[32]));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_jni_getPrivateKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/nonfips/jni/ed_jni.c:264
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, ed.ni_getPrivateKey(keyRef, new byte[32]));
        }
        finally
        {
            ops.resetFlags();
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_jni_initVerify_name()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/nonfips/jni/ed_jni.c:442
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, ed.ni_initVerify(sigRef, keyRef, NAME, null, 0));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void site_jni_update_input()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/nonfips/jni/ed_jni.c:586
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_INPUT, ed.ni_update(sigRef, new byte[8], 0, 8));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    /** JNI moves the private key through the secret helper: one copy, cleansed, per call; FFM makes no copy. */
    @Test
    public void ed_privateKeyLedger()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        int expected = Loader.isFFM() ? 0 : 1;
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long target = specNI.allocate();
        try
        {
            byte[] secret = new byte[32];
            assertSecretLedger(expected,
                    "getPrivateKey", () -> Assertions.assertEquals(32, ed.ni_getPrivateKey(keyRef, secret)));
            assertSecretLedger(expected, "getPrivateKey short", () -> Assertions.assertEquals(JO_OUTPUT_TOO_SMALL,
                    ed.ni_getPrivateKey(keyRef, new byte[31])));
            assertSecretLedger(expected, "decode_privateKey", () -> Assertions.assertEquals(0,
                    ed.ni_decode_privateKey(target, ED25519, secret, 0, 32)));
            assertSecretLedger(0,
                    "getPublicKey", () -> Assertions.assertEquals(32, ed.ni_getPublicKey(keyRef, new byte[32])));
        }
        finally
        {
            specNI.dispose(target);
            specNI.dispose(keyRef);
        }
    }

    private void assertSecretLedger(int expected, String label, Runnable call)
    {
        ops.ledgerReset();
        call.run();
        Assertions.assertEquals(expected, ops.ledgerCreated(OperationsTestNI.LedgerType.SECRET_BYTEARRAY), label);
        Assertions.assertEquals(expected, ops.ledgerDestroyed(OperationsTestNI.LedgerType.SECRET_BYTEARRAY), label);
        Assertions.assertEquals(expected, ops.ledgerCreated(OperationsTestNI.LedgerType.SECRET_CLEANSE), label);
        Assertions.assertEquals(expected, ops.ledgerDestroyed(OperationsTestNI.LedgerType.SECRET_CLEANSE), label);
    }
}
