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

import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceNI;
import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of {@link MLXKEMServiceNI} backed by the FIPS interface
 * library; the glue is the base bridge re-included under renamed exports
 * ({@code interface/fips/jni/mlxkem_fips_jni.c}).
 *
 * <p>Registered per variant, not per family: the 3.5.x module serves all four
 * hybrids, 3.5.8 dropped X448MLKEM1024, and 3.1.2 serves none. See
 * {@code FIPSCapabilities}.
 */
class MLXKEMServiceFIPSJNI implements MLXKEMServiceNI
{
    @Override
    public native long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    @Override
    public native int ni_getPublicKey(long ref, byte[] output);

    @Override
    public native int ni_getPrivateKey(long ref, byte[] output);

    @Override
    public native int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    /**
     * This NI is bound to the FIPS interface library, so the operations it
     * drives run inside the FIPS module - which supplies its own entropy and
     * never consults a caller-supplied SecureRandom (the FIPS lib ctx
     * deliberately omits the java_rand_bridge; see jostle_fips_ctx.c).
     */
    @Override
    public String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}
