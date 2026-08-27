/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.jcajce.provider.AccessException;
import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

public interface SpecNI extends DefaultServiceNI
{

    void ni_dispose(long reference);

    long ni_allocate(int[] err);

    String ni_getName(long keyRef);

    /**
     * The name of the OSSL_PROVIDER that owns this KEY's keymgmt — "fips",
     * "default", and so on — or null when it cannot be determined (null
     * handle, keyless spec, legacy key).
     *
     * <p>Deliberately NOT the same question as
     * {@code OpenSSLFIPSNI.implementingProvider}, which asks which provider
     * implements a NAME in a lib ctx. A key carries its own keymgmt, fixed at
     * creation, and an operation on it is served THERE regardless of which
     * lib ctx drove the operation — measured in
     * {@code fips-c-review/probes/xprovider_key_probe.c}. Only a key-level
     * accessor can express that, which is why MT-14 needed one.
     */
    String ni_getKeyProvider(long keyRef);

    int ni_encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource);

    int ni_decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource);


    default void dispose(long reference)
    {
        ni_dispose(reference);
    }

    default long allocate()
    {
        int[] err = new int[1];
        long ref = ni_allocate(err);
        handleErrors(err[0]);
        return ref;
    }

    default String getKeyProvider(long keyRef)
    {
        return ni_getKeyProvider(keyRef);
    }

    default String getName(long keyRef)
    {
        return ni_getName(keyRef);
    }

    default int encap(long keyRef, String opt, byte[] secret, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource)
    {
        return (int)handleErrors(ni_encap(keyRef, opt, secret, inOff, inLen, out, off, len, randSource));
    }

    default int decap(long keyRef, String opt, byte[] input, int inOff, int inLen, byte[] out, int off, int len, RandSource randSource)
    {
        return (int)handleErrors( ni_decap(keyRef, opt, input, inOff, inLen, out, off, len, randSource));
    }

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }
        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_FAILED_ACCESS_ENCAP_OPP:
                throw new AccessException("unable to access operation string");
            case JO_INPUT_AND_OUTPUT_ALIASED:
                // encap/decap write two distinct buffers (shared secret and
                // encapsulation); passing one array for both would corrupt the
                // result under the JNI whole-array copy-back. Both bridges reject
                // the aliased call with this code (JNI IsSameObject / FFI reference
                // equality) so the NI surface behaves identically.
                throw new IllegalArgumentException("input and output must not be the same array");
        }
        return baseErrorHandler(code);
    }
}
