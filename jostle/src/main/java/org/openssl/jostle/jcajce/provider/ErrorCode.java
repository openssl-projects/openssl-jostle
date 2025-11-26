/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

public enum ErrorCode
{
    JO_SUCCESS(0), /* Success may be >= 0 in some cases */
    JO_FAIL(-1), /* General failure */
    JO_OPENSSL_ERROR(-2),
    JO_PROV_NAME_NULL(-3),
    JO_PROV_NAME_EMPTY(-4),
    JO_INVALID_OP_MODE(-5),
    JO_INVALID_CIPHER(-6),
    JO_INVALID_MODE(-7),
    JO_INVALID_KEY_LEN(-8),
    JO_INVALID_IV_LEN(-9),
    JO_FAILED_ACCESS_KEY(-10),
    JO_FAILED_ACCESS_IV(-11),
    JO_KEY_IS_NULL(-12),
    JO_IV_IS_NULL(-13),
    JO_MODE_TAKES_NO_IV(-14),
    JO_MOD_IN_LEN_NOT_ZERO(-15),

    JO_INPUT_IS_NULL(-16),
    JO_OUTPUT_IS_NULL(-17),
    JO_OUTPUT_TOO_SMALL(-18),
    JO_INPUT_TOO_LONG_INT32(-19),
    JO_OUTPUT_TOO_LONG_INT32(-20),
    JO_INVALID_CIPHER_TEXT(-21),
    JO_FAILED_ACCESS_INPUT(-22),
    JO_FAILED_ACCESS_OUTPUT(-23),
    JO_INPUT_LEN_IS_NEGATIVE(-24),
    JO_OUTPUT_LEN_IS_NEGATIVE(-25),
    JO_INPUT_OFFSET_IS_NEGATIVE(-26),
    JO_OUTPUT_OFFSET_IS_NEGATIVE(-27),
    JO_INPUT_OUT_OF_RANGE(-28),
    JO_OUTPUT_OUT_OF_RANGE(-29),
    JO_NOT_INITIALIZED(-30),
    JO_FINAL_SIZE_LEN_IS_NEGATIVE(-31),
    JO_NOT_BLOCK_ALIGNED(-32),
    JO_CTR_MODE_OVERFLOW(-33),
    JO_OUTPUT_SIZE_INT_OVERFLOW(-34),
    JO_SPEC_HAS_NULL_KEY(-38),
    JO_KEY_SPEC_HAS_NULL_KEY(-39),
    JO_UNEXPECTED_STATE(-40),

    JO_INCORRECT_KEY_TYPE(-41),
    JO_INVALID_KEY_TYPE(-42),
    JO_SIG_IS_NULL(-43),
    JO_SIG_LENGTH_IS_NEGATIVE(-44),
    JO_SIG_LENGTH_IS_ZERO(-45),
    JO_SIG_OUT_OF_RANGE(-46),
    JO_FAILED_ACCESS_SIG(-47),
    JO_CONTEXT_BYTES_TOO_LONG(-48),
    JO_CONTEXT_BYTES_NULL(-49),
    JO_EXTRACTED_KEY_UNEXPECTED_LEN(-50),

    JO_CONTEXT_LEN_PAST_END(-51),
    JO_FAILED_ACCESS_CONTEXT(-52),
    JO_ENCODED_PRIVATE_KEY_LEN(-53),
    JO_ENCODED_PUBLIC_KEY_LEN(-54),
    JO_UNKNOWN_KEY_LEN(-55),
    JO_UNEXPECTED_POINTER_CHANGE(-56),
    JO_UNKNOWN_OSSL_KEY_TYPE(-57),
    JO_UNKNOWN_MU_MODE(-58),
    JO_INVALID_MU_MODE_FOR_VERIFY(-59),
    JO_INVALID_MU_MODE_FOR_SIGN(-60),
    JO_EXTERNAL_MU_INVALID_LEN(-61),
    JO_UNEXPECTED_SIG_LEN_CHANGE(-62),
    JO_INVALID_SEED_LEN(-63),
    JO_SEED_IS_NULL(-64),
    JO_FAILED_ACCESS_SEED(-65),
    JO_INVALID_SEED_LEN_OUT_OF_RANGE(-66),
    JO_SEED_LEN_IS_NEGATIVE(-67),
    JO_INVALID_SLH_DSA_MSG_ENCODING_PARAM(-68),
    JO_INVALID_SLH_DSA_DETERMINISTIC_PARAM(-69),

    JO_FAILED_ACCESS_ENCAP_OPP(-70),
    JO_INVALID_TAG_LEN(-71),
    JO_TAG_IS_NULL(-72),
    JO_TAG_INVALID(-73),

    JO_KDF_PASSWORD_NULL(-74),
    JO_KDF_PASSWORD_FAILED_ACCESS(-75),
    JO_KDF_SALT_NULL(-76),
    JO_KDF_SALT_EMPTY(-77),
    JO_KDF_SALT_FAILED_ACCESS(-78),

    JO_KDF_SCRYPT_N_TOO_SMALL(-79),
    JO_KDF_SCRYPT_N_NOT_POW2(-80),
    JO_KDF_SCRYPT_R_NEGATIVE(-81),
    JO_KDF_SCRYPT_P_NEGATIVE(-82),

    JO_KDF_PBE_ITER_NEGATIVE(-83),
    JO_KDF_PBE_UNKNOWN_DIGEST(-84),

    JO_INVALID_KEY_ENCODING_OPTION(-85),
    JO_FAILED_ACCESS_ENCODING_OPTION(-86),

    JO_UNKNOWN(Integer.MIN_VALUE);

    private int code;


    ErrorCode(int code)
    {
        assert code <= 0;
        this.code = code;
    }

    public static ErrorCode forCode(Supplier supplier)
    {
        try
        {
            int code = supplier.invoke();
            return ErrorCode.forCode(code);
        } catch (Throwable t)
        {
            throw new RuntimeException(t.getMessage(), t);
        }
    }

    public static ErrorCode forCode(long code)
    {
        if (code >= 0)
        {
            return JO_SUCCESS;
        }
        for (ErrorCode errorCode : ErrorCode.values())
        {
            if (errorCode.code == code)
            {
                return errorCode;
            }
        }
        return JO_UNKNOWN;
    }

    public static ErrorCode forCode(int code)
    {
        return ErrorCode.forCode((long) code);
    }

    public int getCode()
    {
        return code;
    }
}
