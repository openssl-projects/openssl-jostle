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

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.rand.RandSource;

/**
 * JNI implementation of {@link SLHDSAServiceNI} backed by the FIPS interface library;
 * the glue is the base bridge re-included under renamed exports
 * ({@code interface/fips/jni/slhdsa_fips_jni.c}).
 *
 * <p>Only registered when the loaded module actually serves the family - the
 * 3.5.x FIPS module does, 3.1.2 does not. See {@code FIPSCapabilities}.
 */
class SLHDSAServiceFIPSJNI implements SLHDSAServiceNI
{
    @Override
    public native long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    @Override
    public native long ni_generateKeyPair(int type, int[] err, byte[] seed, int seedLen, RandSource randSource);

    @Override
    public native int ni_getPrivateKey(long reference, byte[] output);

    @Override
    public native int ni_getPublicKey(long reference, byte[] output);

    @Override
    public native int ni_decode_publicKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native int ni_decode_privateKey(long spec_ref, int keyType, byte[] input, int inputOffset, int inputLen);

    @Override
    public native long ni_allocateSigner(int[] err);

    @Override
    public native int ni_initVerify(long ref, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic);

    @Override
    public native int ni_update(long ref, byte[] b, int off, int len);

    @Override
    public native long ni_sign(long ref, byte[] sig, int offset, RandSource randSource);

    @Override
    public native int ni_verify(long reference, byte[] sigBytes, int len);

    @Override
    public native int ni_initSign(long reference, long keyRef, byte[] context, int contextLen, int messageEncoding, int deterministic, RandSource randSource);

    @Override
    public native void ni_disposeSigner(long reference);

    /**
     * This NI is bound to the FIPS interface library, so the operations it
     * drives run inside the FIPS module - which supplies its own entropy and
     * never consults a caller-supplied SecureRandom (the FIPS lib ctx
     * deliberately omits the java_rand_bridge; see jostle_fips_ctx.c). The PQ
     * SPIs read this through {@code DefaultServiceNI.providerManagesEntropy()}
     * to skip a strength check that would judge a value nothing reads.
     */
    @Override
    public String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}
