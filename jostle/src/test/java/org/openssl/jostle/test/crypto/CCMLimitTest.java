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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;

import java.security.Security;

/**
 * NI-surface input-validation tests for the CCM bridge. These call the
 * raw {@code ni_*} methods (bypassing the throwing wrappers) and assert
 * the exact {@code JO_*} return code, so a silent re-mapping of a check
 * to a different code fails loudly.
 *
 * <p>The validation lives in the bridge layer ({@code ccm_ni_jni.c} /
 * {@code ccm_ni_ffi.c}) and the two bridges are contractually required
 * to return identical codes for identical inputs — the FFI Java layer
 * passes null arrays through as {@code MemorySegment.NULL}/size 0, so
 * the C check fires the same way on both. Every test therefore runs
 * unchanged on JNI and FFI.
 *
 * <p>Boundary probes use exactly {@code boundary + 1} (the smallest
 * rejected value) and are paired with a positive companion proving the
 * boundary sits where it should. Negative-int probes feed both
 * {@code -1} and {@code Integer.MIN_VALUE}.
 */
public class CCMLimitTest
{
    CCMCipherNI ccmCipherNI = TestNISelector.getCCMCipher();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private long newCtx()
    {
        int[] err = new int[1];
        long ref = ccmCipherNI.ni_makeInstance(CCMCipherNI.AES128, err);
        Assertions.assertEquals(0, err[0], "ni_makeInstance(AES128) should succeed");
        return ref;
    }

    private long newInitedCtx()
    {
        long ref = newCtx();
        Assertions.assertEquals(0,
                ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], 16),
                "ni_init should succeed");
        return ref;
    }

    // -----------------------------------------------------------------
    // ni_init validation
    // -----------------------------------------------------------------

    @Test
    public void init_nullRef() throws Exception
    {
        int code = ccmCipherNI.ni_init(0L, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], 16);
        Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);
    }

    @Test
    public void init_nullKey() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx();
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, null, new byte[12], 16);
            Assertions.assertEquals(ErrorCode.JO_KEY_IS_NULL.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void init_nullIv() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx();
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], null, 16);
            Assertions.assertEquals(ErrorCode.JO_IV_IS_NULL.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void init_negativeTagLen_minusOne() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx();
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], -1);
            Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void init_negativeTagLen_minValue() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx();
            int code = ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], Integer.MIN_VALUE);
            Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    /**
     * NI-surface boundary for the C {@code valid_ccm_tag_len}
     * ({@code ccm_ctx_init}): every valid tag length is accepted and each
     * adjacent value is rejected. The negative-tag tests above are caught
     * by the bridge's {@code tag_len < 0} check before {@code valid_ccm_tag_len}
     * runs; this is the only coverage of its positive set-membership
     * rejection (unreachable through the JCE path, which validates in
     * CCMCipherSpi before calling native). Bridge-agnostic — runs on both
     * JNI and FFI.
     */
    @Test
    public void init_tagLen_setMembershipBoundary() throws Exception
    {
        // Valid byte lengths {4,6,8,10,12,14,16} must be accepted.
        for (int tagLen : new int[]{4, 6, 8, 10, 12, 14, 16})
        {
            long ref = newCtx();
            try
            {
                Assertions.assertEquals(0,
                        ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], tagLen),
                        "tagLen=" + tagLen + " (valid) must be accepted");
            }
            finally
            {
                ccmCipherNI.ni_dispose(ref);
            }
        }
        // 3 (below min 4), the odd byte counts between the valid evens
        // (5,7,9,11,13,15), and 17 (above max 16) — both neighbours of
        // every valid value must be rejected.
        for (int tagLen : new int[]{3, 5, 7, 9, 11, 13, 15, 17})
        {
            long ref = newCtx();
            try
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_TAG_LEN.getCode(),
                        ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[12], tagLen),
                        "tagLen=" + tagLen + " (invalid) must be rejected");
            }
            finally
            {
                ccmCipherNI.ni_dispose(ref);
            }
        }
    }

    /**
     * NI-surface boundary for ccm_ctx_init's iv_len (nonce) check: 7..13
     * bytes accepted, 0/6/14 rejected with JO_INVALID_IV_LEN. Like the
     * tag-length check this is unreachable through the JCE path
     * (CCMCipherSpi validates the nonce length first), so the NI surface
     * is the only place to probe it. Bridge-agnostic.
     */
    @Test
    public void init_ivLen_boundary() throws Exception
    {
        for (int ivLen : new int[]{7, 13})
        {
            long ref = newCtx();
            try
            {
                Assertions.assertEquals(0,
                        ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[ivLen], 16),
                        "ivLen=" + ivLen + " (valid) must be accepted");
            }
            finally
            {
                ccmCipherNI.ni_dispose(ref);
            }
        }
        for (int ivLen : new int[]{0, 6, 14})
        {
            long ref = newCtx();
            try
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_IV_LEN.getCode(),
                        ccmCipherNI.ni_init(ref, CCMCipherNI.OP_ENCRYPT, new byte[16], new byte[ivLen], 16),
                        "ivLen=" + ivLen + " (invalid) must be rejected");
            }
            finally
            {
                ccmCipherNI.ni_dispose(ref);
            }
        }
    }

    /**
     * NI-surface check for ccm_ctx_init's op-mode validation: anything
     * other than ENCRYPT/DECRYPT is rejected with JO_INVALID_OP_MODE.
     * (The bridge does not validate op_mode, so this exercises the util
     * check directly.)
     */
    @Test
    public void init_invalidOpMode() throws Exception
    {
        for (int opMode : new int[]{0, 3, 99})
        {
            long ref = newCtx();
            try
            {
                Assertions.assertEquals(ErrorCode.JO_INVALID_OP_MODE.getCode(),
                        ccmCipherNI.ni_init(ref, opMode, new byte[16], new byte[12], 16),
                        "opMode=" + opMode + " must be rejected");
            }
            finally
            {
                ccmCipherNI.ni_dispose(ref);
            }
        }
    }

    // -----------------------------------------------------------------
    // ni_doFinal validation — null / negative
    // -----------------------------------------------------------------

    @Test
    public void doFinal_nullRef() throws Exception
    {
        int code = ccmCipherNI.ni_doFinal(0L, null, 0, new byte[16], 0, 16, new byte[32], 0);
        Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);
    }

    @Test
    public void doFinal_negativeAadLen_minusOne() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, new byte[8], -1, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeAadLen_minValue() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, new byte[8], Integer.MIN_VALUE, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_nullAadWithNonZeroLen() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 5, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_IS_NULL.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_nullInput() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, null, 0, 0, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_IS_NULL.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeInOff_minusOne() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], -1, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_OFFSET_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeInOff_minValue() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], Integer.MIN_VALUE, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_OFFSET_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeInLen_minusOne() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, -1, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeInLen_minValue() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, Integer.MIN_VALUE, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_nullOutput() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, null, 0);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_IS_NULL.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeOutOff_minusOne() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], -1);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OFFSET_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_negativeOutOff_minValue() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], Integer.MIN_VALUE);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OFFSET_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // ni_doFinal range checks — boundary + 1 probes and positive companions
    // -----------------------------------------------------------------

    @Test
    public void doFinal_aadLenPastEnd() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            // aad buffer is 8 bytes; aadLen 9 is the smallest rejected value.
            int code = ccmCipherNI.ni_doFinal(ref, new byte[8], 9, new byte[16], 0, 16, new byte[32], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_inputLenPastEnd() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            // input 16 bytes, offset 0, len 17 (0 + 17 > 16).
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 17, new byte[64], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_inputOffsetPastEnd() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            // input 16 bytes, offset 16, len 1 (16 + 1 > 16).
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 16, 1, new byte[64], 0);
            Assertions.assertEquals(ErrorCode.JO_INPUT_OUT_OF_RANGE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_inputBoundary_offsetAtEnd_lenZero_succeeds() throws Exception
    {
        // Positive companion: offset == size with len 0 is in range (16 + 0 == 16),
        // so the bridge accepts it; empty-plaintext encrypt returns just the tag (16).
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 16, 0, new byte[16], 0);
            Assertions.assertEquals(16, code, "empty-plaintext encrypt should write the 16-byte tag");
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_outputOffsetPastEnd() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            // output 32 bytes; outOff 33 is the smallest rejected value.
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 33);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_OUT_OF_RANGE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void doFinal_outputOffsetAtEnd_passesRangeCheck() throws Exception
    {
        // Positive companion: outOff == size passes the range check (outOff > size
        // is the reject condition), so the failure is the downstream
        // JO_OUTPUT_TOO_SMALL (out_avail == 0 < tag_len), NOT JO_OUTPUT_OUT_OF_RANGE.
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_doFinal(ref, null, 0, new byte[16], 0, 16, new byte[32], 32);
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_SMALL.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // ni_getOutputSize validation
    // -----------------------------------------------------------------

    @Test
    public void getOutputSize_nullRef() throws Exception
    {
        int code = ccmCipherNI.ni_getOutputSize(0L, CCMCipherNI.OP_ENCRYPT, 16);
        Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), code);
    }

    @Test
    public void getOutputSize_negativeInputLen_minusOne() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, -1);
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    @Test
    public void getOutputSize_negativeInputLen_minValue() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx();
            int code = ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, Integer.MIN_VALUE);
            Assertions.assertEquals(ErrorCode.JO_INPUT_LEN_IS_NEGATIVE.getCode(), code);
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // ccm_do_one_shot / ccm_ctx_get_output_size value + boundary checks
    // -----------------------------------------------------------------

    /**
     * Decrypt boundary in ccm_do_one_shot: a ciphertext shorter than the
     * tag cannot carry one, so in_len &lt; tag_len is rejected with
     * JO_INVALID_CIPHER_TEXT before any EVP work. (The in_len == tag_len
     * accept side — empty plaintext — is covered by the empty-plaintext
     * agreement round-trips.)
     */
    @Test
    public void doFinal_decryptInputShorterThanTag() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx();
            Assertions.assertEquals(0,
                    ccmCipherNI.ni_init(ref, CCMCipherNI.OP_DECRYPT, new byte[16], new byte[12], 16));
            // in_len = 15 < tag_len 16.
            Assertions.assertEquals(ErrorCode.JO_INVALID_CIPHER_TEXT.getCode(),
                    ccmCipherNI.ni_doFinal(ref, null, 0, new byte[15], 0, 15, new byte[16], 0));
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    /**
     * Decrypt output-too-small boundary (ccm_do_one_shot): a valid-length
     * ciphertext (in_len &gt;= tag_len) with an output buffer smaller than
     * the recovered plaintext (ct_len = in_len - tag_len) is rejected with
     * JO_OUTPUT_TOO_SMALL before any EVP work — the decrypt-side mirror of
     * the encrypt output-size check.
     */
    @Test
    public void doFinal_decryptOutputTooSmall() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx();
            Assertions.assertEquals(0,
                    ccmCipherNI.ni_init(ref, CCMCipherNI.OP_DECRYPT, new byte[16], new byte[12], 16));
            // in_len=32 -> ct_len=16, but output is only 15 bytes.
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_SMALL.getCode(),
                    ccmCipherNI.ni_doFinal(ref, null, 0, new byte[32], 0, 32, new byte[15], 0));
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    /**
     * ccm_ctx_get_output_size value + boundary behaviour (tag_len = 16):
     * encrypt adds the tag; decrypt subtracts it and floors at 0 when the
     * input is shorter than the tag (the input_len &lt; tag_len branch);
     * an unknown op-mode yields JO_INVALID_OP_MODE.
     */
    @Test
    public void getOutputSize_valuesAndBoundary() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx(); // tag_len = 16
            // Encrypt: N -> N + tag_len.
            Assertions.assertEquals(16, ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, 0));
            Assertions.assertEquals(116, ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, 100));
            // Decrypt: floor at 0 below tag_len, else N - tag_len. Boundary at 16.
            Assertions.assertEquals(0, ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_DECRYPT, 15));
            Assertions.assertEquals(0, ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_DECRYPT, 16));
            Assertions.assertEquals(1, ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_DECRYPT, 17));
            // Unknown op-mode.
            Assertions.assertEquals(ErrorCode.JO_INVALID_OP_MODE.getCode(),
                    ccmCipherNI.ni_getOutputSize(ref, 99, 16));
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    /**
     * Encrypt-side INT32 overflow guard in ccm_ctx_get_output_size
     * (tag_len = 16): input_len + tag_len is rejected with
     * JO_OUTPUT_TOO_LONG_INT32 once it would exceed INT32_MAX. This is
     * reachable with an ordinary Java int (Integer.MAX_VALUE), not just
     * via OPS injection. Boundary is at INT32_MAX - tag_len.
     */
    @Test
    public void getOutputSize_encryptOverflowBoundary() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newInitedCtx(); // tag_len = 16
            // Largest input whose ct||tag still fits int32: (MAX-16)+16 == MAX.
            Assertions.assertEquals(Integer.MAX_VALUE,
                    ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, Integer.MAX_VALUE - 16));
            // One past the boundary, and the extreme, must overflow.
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_LONG_INT32.getCode(),
                    ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, Integer.MAX_VALUE - 15));
            Assertions.assertEquals(ErrorCode.JO_OUTPUT_TOO_LONG_INT32.getCode(),
                    ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, Integer.MAX_VALUE));
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }

    /**
     * ccm_ctx_get_output_size on a created-but-not-initialised ctx returns
     * JO_NOT_INITIALIZED (the initialized state-check fires before the
     * op-mode branches).
     */
    @Test
    public void getOutputSize_notInitialised() throws Exception
    {
        long ref = 0;
        try
        {
            ref = newCtx(); // created, NOT initialised
            Assertions.assertEquals(ErrorCode.JO_NOT_INITIALIZED.getCode(),
                    ccmCipherNI.ni_getOutputSize(ref, CCMCipherNI.OP_ENCRYPT, 16));
        }
        finally
        {
            ccmCipherNI.ni_dispose(ref);
        }
    }
}
