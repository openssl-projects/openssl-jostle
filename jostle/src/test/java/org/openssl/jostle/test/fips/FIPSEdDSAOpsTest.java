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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Every EdDSA fault site in the FIPS tree, one cell per site, driven through the FIPS interface library. Cells
 * run only where the module serves the Ed key types; the JNI access sites run on the JNI bridge only.
 */
public class FIPSEdDSAOpsTest
{
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

    private final EDServiceNI ed = FIPSNISelector.EDServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;
    private final OperationsTestNI ops = FIPSNISelector.OperationsTestNI;

    @BeforeAll
    public static void beforeAll()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    @BeforeEach
    public void beforeEach()
    {
        if (ops.opsTestAvailable())
        {
            ops.resetFlags();
        }
    }

    /**
     * Runs on every module and build: the Ed key-pair generator is registered exactly when the module serves the
     * Ed25519 key type, so the skips below are the module's absence and not a lost registration.
     */
    @Test
    public void edServedIffModuleImplementsIt()
    {
        boolean registered = TestUtil.addFipsProvider().getService("KeyPairGenerator", "ED25519") != null;
        Assertions.assertEquals(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), registered,
                "the Ed registration disagrees with the loaded module");
    }

    @Test
    public void fips_generateKeyPair_ctxNew()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        try
        {
            // Exercises interface/fips/util/edec.c:52
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            int[] err = new int[1];
            Assertions.assertEquals(0L, ed.ni_generateKeyPair(ED25519, err, RND));
            Assertions.assertEquals(errorAt(1010), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_generateKeyPair_keygenInit()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        try
        {
            // Exercises interface/fips/util/edec.c:58
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_3);
            int[] err = new int[1];
            Assertions.assertEquals(0L, ed.ni_generateKeyPair(ED25519, err, RND));
            Assertions.assertEquals(errorAt(1011), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_generateKeyPair_keygen()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        try
        {
            // Exercises interface/fips/util/edec.c:64
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_4);
            int[] err = new int[1];
            Assertions.assertEquals(0L, ed.ni_generateKeyPair(ED25519, err, RND));
            Assertions.assertEquals(errorAt(1012), err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_generateKeyPair_nullKey()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        try
        {
            // Exercises interface/fips/util/edec.c:70
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            int[] err = new int[1];
            Assertions.assertEquals(0L, ed.ni_generateKeyPair(ED25519, err, RND));
            Assertions.assertEquals(JO_OPENSSL_ERROR, err[0]);
        }
        finally
        {
            ops.resetFlags();
        }
    }

    @Test
    public void fips_getPublicKey_sizeQuery()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/util/edec.c:111
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
    public void fips_getPublicKey_fill()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/util/edec.c:128
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
    public void fips_getPublicKey_overflow()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/util/edec.c:133
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
    public void fips_getPrivateKey_sizeQuery()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/util/edec.c:161
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
    public void fips_getPrivateKey_fill()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/util/edec.c:177
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
    public void fips_getPrivateKey_overflow()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/util/edec.c:182
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
    public void fips_decodePrivateKey_nullKey()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/fips/util/edec.c:288
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
    public void fips_decodePublicKey_nullKey()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/fips/util/edec.c:365
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
    public void fips_allocateSigner_bio()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        try
        {
            // Exercises interface/fips/util/edec.c:394
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
    public void fips_initSign_mdCtxNew()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/util/edec.c:483
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(errorAt(1000), ed.ni_initSign(sigRef, keyRef, NAME, null, 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_initSign_digestSignInit()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/util/edec.c:504
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(errorAt(1001), ed.ni_initSign(sigRef, keyRef, NAME, null, 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_initVerify_mdCtxNew()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/util/edec.c:563
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(errorAt(1003), ed.ni_initVerify(sigRef, keyRef, NAME, null, 0));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_initVerify_digestVerifyInit()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/util/edec.c:582
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(errorAt(1004), ed.ni_initVerify(sigRef, keyRef, NAME, null, 0));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_sign_sizeQuery()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initSign(sigRef, keyRef, NAME, null, 0, RND);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/util/edec.c:676
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_sign(sigRef, null, 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_sign_overflow()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initSign(sigRef, keyRef, NAME, null, 0, RND);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/util/edec.c:682
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
    public void fips_sign_fill()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initSign(sigRef, keyRef, NAME, null, 0, RND);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/util/edec.c:700
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_2);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_sign(sigRef, new byte[64], 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_sign_lengthChange()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initSign(sigRef, keyRef, NAME, null, 0, RND);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/util/edec.c:706
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_LEN_CHANGE_1);
            Assertions.assertEquals(JO_UNEXPECTED_SIG_LEN_CHANGE, ed.ni_sign(sigRef, new byte[64], 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_verify_error()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initVerify(sigRef, keyRef, NAME, null, 0);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/util/edec.c:755
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_OPENSSL_ERROR_1);
            Assertions.assertEquals(JO_OPENSSL_ERROR, ed.ni_verify(sigRef, new byte[64], 64));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_jni_decodePublicKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:114
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
    public void fips_jni_decodePrivateKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long src = ed.generateKeyPair(ED25519, RND);
        byte[] publicBytes = new byte[32];
        byte[] privateBytes = new byte[32];
        ed.getPublicKey(src, publicBytes);
        ed.getPrivateKey(src, privateBytes);
        long target = specNI.allocate();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:173
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
    public void fips_jni_getPublicKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:230
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
    public void fips_jni_getPrivateKey_access()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:264
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
    public void fips_jni_initSign_name()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:308
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_2);
            Assertions.assertEquals(JO_UNABLE_TO_ACCESS_NAME, ed.ni_initSign(sigRef, keyRef, NAME, null, 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_jni_initSign_context()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:327
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_CONTEXT,
                    ed.ni_initSign(sigRef, keyRef, NAME, new byte[1], 1, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_jni_sign_output()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initSign(sigRef, keyRef, NAME, null, 0, RND);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:392
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_OUTPUT, ed.ni_sign(sigRef, new byte[64], 0, RND));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_jni_initVerify_name()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:442
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
    public void fips_jni_initVerify_context()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:462
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_CONTEXT, ed.ni_initVerify(sigRef, keyRef, NAME, new byte[1], 1));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_jni_verify_sig()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        ed.initVerify(sigRef, keyRef, NAME, null, 0);
        ed.update(sigRef, new byte[8], 0, 8);
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:527
            ops.setFlag(OperationsTestNI.OpsTestFlag.OPS_FAILED_ACCESS_1);
            Assertions.assertEquals(JO_FAILED_ACCESS_SIG, ed.ni_verify(sigRef, new byte[64], 64));
        }
        finally
        {
            ops.resetFlags();
            ed.disposeSigner(sigRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void fips_jni_update_input()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
        Assumptions.assumeFalse(Loader.isFFM());
        long keyRef = ed.generateKeyPair(ED25519, RND);
        long sigRef = ed.allocateSigner();
        try
        {
            // Exercises interface/fips/jni/ed_jni.c:586
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
    public void fips_privateKeyLedger()
    {
        Assumptions.assumeTrue(ops.opsTestAvailable());
        Assumptions.assumeTrue(FIPSTestUtil.moduleServesKeyMgmt("ED25519"), "the module serves no Ed key type");
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
