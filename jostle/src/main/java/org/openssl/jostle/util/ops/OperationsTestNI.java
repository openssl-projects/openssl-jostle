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

/**
 * Operations tests:
 * <p>
 * Some code paths are mostly impossible to verify during normal testing because we would
 * need to induce, for example, a failure within the JVM or some other circumstance that can only
 * occur under very adverse conditions or via directly modifying an opcode in a library during loading.
 *
 * This interface gives us access to a series of flags that will induce execution of the same paths but without
 * the need to actually stage the error. It allows us to prove that our code will handle, in some way, those error
 * conditions if they were to occur.
 *
 * Operations tests require the interface library to be built with the macro JOSTLE_OPS defined or define
 * the environmental variable JOSTLE_OPS_TEST when invoking cmake.
 *
 * ie export JOSTLE_OPS_TEST=1
 *
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

    /**
     * Set a ops test flag true
     * @param flag the flag
     */
    default void setFlag(OpsTestFlag flag) {
        assert opsTestAvailable();
        setOpsTestFlag(flag.ordinal(),1);
    }

    default void resetFlags()
    {
        for (OpsTestFlag value : OpsTestFlag.values())
        {
            setOpsTestFlag(value.ordinal(),0);
        }
    }

    enum OpsTestFlag
    {
        OPS_INT32_OVERFLOW_1,
        OPS_INT32_OVERFLOW_2,
        OPS_INT32_OVERFLOW_3,
        OPS_FAILED_ACCESS_1,
        OPS_FAILED_ACCESS_2,
        OPS_FAILED_ACCESS_3,
        OPS_POINTER_CHANGE,
        OPS_OPENSSL_ERROR_1,
        OPS_OPENSSL_ERROR_2,
        OPS_OPENSSL_ERROR_3,
        OPS_OPENSSL_ERROR_4,
        OPS_OPENSSL_ERROR_5,
        OPS_OPENSSL_ERROR_6,
        OPS_LEN_CHANGE_1

    }

}
