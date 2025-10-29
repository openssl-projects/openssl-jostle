//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef BC_OSSL_ERR_CODES_H
#define BC_OSSL_ERR_CODES_H

/*
 * These translate to return codes often in a situation where 0 is a
 * valid value, for example, a call to update may accept all input but emit 0 bytes
 * of output making it a valid call that didn't emit anything at that time.
 */

#define JO_SUCCESS 0 /* Success  */

/* A failure is any value less than zero */
#define JO_FAIL -1 /* General failure */
#define JO_OPENSSL_ERROR -2
#define JO_PROV_NAME_NULL -3
#define JO_PROV_NAME_EMPTY -4

#define JO_INVALID_OP_MODE -5
#define JO_INVALID_CIPHER -6
#define JO_INVALID_MODE -7
#define JO_INVALID_KEY_LEN -8
#define JO_INVALID_IV_LEN -9
#define JO_FAILED_ACCESS_KEY -10
#define JO_FAILED_ACCESS_IV -11
#define JO_KEY_IS_NULL -12
#define JO_IV_IS_NULL -13
#define JO_MODE_TAKES_NO_IV -14
#define JO_MOD_IN_LEN_NOT_ZERO -15
#define JO_INPUT_IS_NULL -16
#define JO_OUTPUT_IS_NULL -17
#define JO_OUTPUT_TOO_SMALL -18
#define JO_INPUT_TOO_LONG_INT32 -19
#define JO_OUTPUT_TOO_LONG_INT32 -20
#define JO_INVALID_CIPHER_TEXT -21
#define JO_FAILED_ACCESS_INPUT -22
#define JO_FAILED_ACCESS_OUTPUT -23
#define JO_INPUT_LEN_IS_NEGATIVE -24
#define JO_OUTPUT_LEN_IS_NEGATIVE -25
#define JO_INPUT_OFFSET_IS_NEGATIVE -26
#define JO_OUTPUT_OFFSET_IS_NEGATIVE -27
#define JO_INPUT_OUT_OF_RANGE -28
#define JO_OUTPUT_OUT_OF_RANGE -29
#define JO_NOT_INITIALIZED -30
#define JO_FINAL_SIZE_LEN_IS_NEGATIVE -31
#define JO_NOT_BLOCK_ALIGNED -32
#define JO_CTR_MODE_OVERFLOW -33
#define JO_OUTPUT_SIZE_INT_OVERFLOW -34

// #define BC_REF_ARRAY_WRONG_SIZE -35
// #define BC_REF_ARRAY_NULL -36
// #define BC_REF_UNABLE_TO_ACCESS_REF_ARRAY -37
#define JO_KEY_SPEC_IS_NULL -38
#define JO_KEY_SPEC_HAS_NULL_KEY -39
#define JO_UNEXPECTED_STATE -40
#define JO_INCORRECT_KEY_TYPE -41

#define JO_INVALID_KEY_TYPE -42
#define JO_SIG_IS_NULL -43
#define JO_SIG_LENGTH_IS_NEGATIVE -44
//#define JO_SIG_LENGTH_IS_ZERO -45
#define JO_SIG_OUT_OF_RANGE -46
#define JO_FAILED_ACCESS_SIG -47
#define JO_CONTEXT_BYTES_TOO_LONG -48
#define JO_CONTEXT_BYTES_NULL -49
#define JO_EXTRACTED_KEY_UNEXPECTED_LEN -50
#define JO_CONTEXT_LEN_PAST_END -51
#define JO_FAILED_ACCESS_CONTEXT -52

#define JO_ENCODED_PRIVATE_KEY_LEN -53
#define JO_ENCODED_PUBLIC_KEY_LEN -54
#define JO_UNKNOWN_KEY_LEN -55
#define JO_UNEXPECTED_POINTER_CHANGE -56
#define JO_UNKNOWN_OSSL_KEY_TYPE -57
#define JO_UNKNOWN_MU_MODE -58
#define JO_INVALID_MU_MODE_FOR_VERIFY -59
#define JO_INVALID_MU_MODE_FOR_SIGN -60
#define JO_EXTERNAL_MU_INVALID_LEN -61
#define JO_UNEXPECTED_SIG_LEN_CHANGE -62
#define JO_INVALID_SEED_LEN -63
#define JO_SEED_IS_NULL -64
#define JO_FAILED_ACCESS_SEED -65
#define JO_INVALID_SEED_LEN_OUT_OF_RANGE -66
#define JO_SEED_LEN_IS_NEGATIVE -67
#define JO_INVALID_SLH_DSA_MSG_ENCODING_PARAM -68
#define JO_INVALID_SLH_DSA_DETERMINISTIC_PARAM -69

#define JO_FAILED_ACCESS_ENCAP_OPP -70
#define JO_INVALID_TAG_LEN -71
#define JO_TAG_IS_NULL -72
#define JO_TAG_INVALID -73

#define JO_KDF_PASSWORD_NULL -74
#define JO_KDF_PASSWORD_FAILED_ACCESS -75
#define JO_KDF_SALT_NULL -76
#define JO_KDF_SALT_EMPTY -77
#define JO_KDF_SALT_FAILED_ACCESS -78

#define JO_KDF_SCRYPT_N_NEGATIVE -79
#define JO_KDF_SCRYPT_R_NEGATIVE -80
#define JO_KDF_SCRYPT_P_NEGATIVE -81

#define JO_KDF_PBE_ITER_NEGATIVE -82
#define JO_KDF_PBE_UNKNOWN_DIGEST -83
#define JO_KDF_OUTPUT_NULL -84


#endif //BC_OSSL_ERR_CODES_H
