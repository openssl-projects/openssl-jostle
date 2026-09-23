/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.ops;

import org.openssl.jostle.rand.RandSource;

/**
 * Operations tests:
 * <p>
 * Some code paths are mostly impossible to verify during normal testing because we would
 * need to induce, for example, a failure within the JVM or some other circumstance that can only
 * occur under very adverse conditions or via directly modifying an opcode in a library during loading.
 * <p>
 * This interface gives us access to a series of flags that will induce execution of the same paths but without
 * the need to actually stage the error. It allows us to prove that our code will handle, in some way, those error
 * conditions if they were to occur.
 * <p>
 * Operations tests require the interface library to be built with the macro JOSTLE_OPS defined or define
 * the environmental variable JOSTLE_OPS_TEST when invoking cmake.
 * <p>
 * ie export JOSTLE_OPS_TEST=1
 * <p>
 * Cmake ignores the value of JOSTLE_OPS_TEST and only cares if it is set.
 */
public interface OperationsTestNI
{
    /**
     * Operations tests available.
     *
     * @return true = available
     *
     */
    boolean opsTestAvailable();


    void setOpsTestFlag(int flag, int value);


    int op_getEntropy(byte[] out, int len, int strength, boolean predictionResistant, RandSource randSource);

    /**
     * Create a DRBG whose entropy is the bytes given rather than the real
     * chain, so a known-answer vector can be reproduced. Operations-test
     * builds only.
     *
     * <p>The handle is an ordinary rand context and carries no marking: the
     * guard is the build, not the type. Generate, reseed and dispose of it
     * through {@code RandServiceNI}, so a vector exercises the shipped code
     * rather than a test-only generator.
     *
     * <p>Pass an EMPTY array, never null, for a vector with no personalisation
     * string: with the derivation function on, OpenSSL derives different bytes
     * from a null one and raises nothing. Null aborts.
     *
     * @return the handle, or 0 with {@code err[0]} set
     */
    long op_createTestDrbg(String mechanism, String variant, boolean useDerivationFunction,
                           int strength, boolean predictionResistant, byte[] personalizationString,
                           byte[] entropy, byte[] nonce, int[] err);

    /**
     * Re-set the fixed entropy on a handle {@link #op_createTestDrbg} returned,
     * so reseed and prediction-resistance vectors can be driven. OpenSSL takes
     * fresh entropy before a reseed and before each prediction-resistance
     * generate, not one stream consumed in order.
     *
     * <p>Aborts on a handle that carries no fixed entropy.
     *
     * @return {@code 0}, or a negative error code
     */
    int op_setTestEntropy(long ref, byte[] entropy);

    /**
     * Whether the lib ctx backing SecureRandom pins approved mode. Read-only,
     * operations-test builds only.
     *
     * <p>It answers about the context the service actually fetches through, so
     * a test can assert the fixed-entropy hook leaves the FIPS tree's rand ctx
     * unrelaxed rather than inferring it from a provider name.
     *
     * <p>Aborts before the provider has initialised its rand ctx, so call it
     * after registration.
     */
    boolean op_randLibctxFipsEnabled();

    /**
     * Creates counted for a ledger type since the last reset, in the library
     * this NI drives. Operations-test builds only; counts only what a
     * Java-held handle owns, so a failed create counts nothing.
     */
    int op_ledgerCreated(int type);

    /** Destroys counted for a ledger type since the last reset. */
    int op_ledgerDestroyed(int type);

    /** Zeroes every ledger count in this library. */
    void op_ledgerReset();

    default int ledgerCreated(LedgerType type)
    {
        assert opsTestAvailable();
        return op_ledgerCreated(type.ordinal());
    }

    default int ledgerDestroyed(LedgerType type)
    {
        assert opsTestAvailable();
        return op_ledgerDestroyed(type.ordinal());
    }

    default void ledgerReset()
    {
        assert opsTestAvailable();
        op_ledgerReset();
    }

    /**
     * Set ops test flag true
     *
     * @param flag the flag
     */
    default void setFlag(OpsTestFlag flag)
    {
        assert opsTestAvailable();
        setOpsTestFlag(flag.ordinal(), 1);
    }

    default void resetFlags()
    {
        for (OpsTestFlag value : OpsTestFlag.values())
        {
            setOpsTestFlag(value.ordinal(), 0);
        }
    }

    default int getRandDataViaOpenSSL(byte[] out, int len, int strength, boolean predictionResistant, RandSource randSource)
    {
        assert opsTestAvailable();
        return op_getEntropy(out, len, strength, predictionResistant, randSource);
    }

    enum OpsTestFlag
    {
        OPS_INT32_OVERFLOW_1,
        OPS_INT32_OVERFLOW_2,
        OPS_INT32_OVERFLOW_3,

        OPS_FAILED_ACCESS_1,
        OPS_FAILED_ACCESS_2,
        OPS_FAILED_ACCESS_3,
        OPS_FAILED_ACCESS_4,

        OPS_POINTER_CHANGE,

        OPS_OPENSSL_ERROR_1,
        OPS_OPENSSL_ERROR_2,
        OPS_OPENSSL_ERROR_3,
        OPS_OPENSSL_ERROR_4,
        OPS_OPENSSL_ERROR_5,
        OPS_OPENSSL_ERROR_6,

        OPS_LEN_CHANGE_1,

        OPS_FAILED_CREATE_1,
        OPS_FAILED_CREATE_2,

        OPS_FAILED_INIT_1,
        OPS_FAILED_INIT_2,

        OPS_FAILED_SET_1,
        OPS_FAILED_SET_2,

        OPS_THREAD_ATTACH_1,
        OPS_JNI_FAIL_CREATE_1,

        OPS_SHORT_SIZE_1,
        OPS_RAND_UP_CALL_NULL,

        OPS_ALTERNATE_1,
        OPS_ALTERNATE_2,
        OPS_ALTERNATE_3,

        OPS_OPENSSL_ERROR_7,
        OPS_OPENSSL_ERROR_8,
        OPS_OPENSSL_ERROR_9,
        OPS_OPENSSL_ERROR_10,
        OPS_OPENSSL_ERROR_11,
        OPS_OPENSSL_ERROR_12,

        // Appended out of family order deliberately: setFlag uses ordinal()
        // as the native slot index, so new flags MUST go at the end to match
        // their is_ops_set(N) slot in interface/nonfips/util/ops.h.
        OPS_FAILED_ACCESS_5,
        OPS_ALTERNATE_4,
        OPS_FAILED_ACCESS_6,
        OPS_ALTERNATE_5,
        OPS_FAILED_ACCESS_7,
        OPS_FAILED_ACCESS_8,
        OPS_FAILED_ACCESS_9,
        OPS_LEDGER_SKIP_FREE_1,
    }

    /**
     * Native context types the disposal ledger counts. The ordinal is the C
     * enum value in interface/nonfips/util/ops.h, so new types are APPENDED,
     * never inserted, the same trap as {@link OpsTestFlag}.
     */
    enum LedgerType
    {
        MD_CTX,
        MAC_CTX,
        BLOCK_CIPHER_CTX,
        CCM_CTX,
        KEY_SPEC,
        ASN1_CTX,
        RSA_CTX,
        RSA_OAEP_CTX,
        RSA_PKCS1_CTX,
        DSA_CTX,
        EC_CTX,
        EC_KEX_CTX,
        DH_KEX_CTX,
        EDEC_CTX,
        MLDSA_CTX,
        SLH_DSA_CTX,
        KS_CTX,
        RAND_CTX,
        X509_CERT,
        X509_CRL,
    }

}
