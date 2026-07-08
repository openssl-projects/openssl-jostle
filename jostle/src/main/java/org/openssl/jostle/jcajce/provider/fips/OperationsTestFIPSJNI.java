/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * JNI implementation of {@link OperationsTestNI} backed by the FIPS interface
 * library (libinterface_fips_jni). The distinct fully-qualified class name
 * gives the FIPS library its own Java_*_fips_OperationsTestFIPSJNI_* symbols -
 * the glue (interface/jni/ops_fips_jni.c) is the base jni/ops.c re-included
 * under renamed exports, so both libraries share one wrapper implementation.
 *
 * <p>Like the base {@code OperationsTestJNI}, the native symbols exist only
 * when the FIPS library was built with JOSTLE_OPS (a JOSTLE_OPS_TEST build);
 * {@link #opsTestAvailable()} probes for them and returns false otherwise.
 */
class OperationsTestFIPSJNI implements OperationsTestNI
{
    private static Boolean opsTestAvailable;

    @Override
    public boolean opsTestAvailable()
    {
        if (opsTestAvailable == null)
        {
            try
            {
                setOpsTestFlag(0, 0);
                opsTestAvailable = true;
            }
            catch (UnsatisfiedLinkError e)
            {
                opsTestAvailable = false;
            }
        }
        return opsTestAvailable;
    }

    @Override
    public native void setOpsTestFlag(int flag, int value);

    @Override
    public native int op_getEntropy(byte[] out, int len, int strength, boolean predictionResistant, RandSource randSource);
}
