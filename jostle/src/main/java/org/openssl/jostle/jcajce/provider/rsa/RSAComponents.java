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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;

/**
 * Shared helper that fetches a single RSA component from the native
 * EVP_PKEY and reconstitutes it as a positive {@link BigInteger}.
 *
 * <p>The component-availability contract differs by component:
 * <ul>
 *   <li>{@code modulus}, {@code public exponent} (on a public key) and
 *       {@code modulus}, {@code private exponent} (on a private key)
 *       MUST be present — absence is a programming error and is
 *       surfaced as a thrown exception by {@link #getRequired}.</li>
 *   <li>CRT components on a private key MAY be absent if the key was
 *       constructed from a non-CRT spec; {@link #getOptional} returns
 *       null in that case to honour the {@code RSAPrivateCrtKey} JCA
 *       contract.</li>
 * </ul>
 */
final class RSAComponents
{
    private RSAComponents() {}

    /**
     * Fetches a component that must exist on this key. Throws if the
     * native call fails for any reason.
     */
    static BigInteger getRequired(RSAServiceNI rsaServiceNI, PKEYKeySpec spec, int component)
    {
        // Synchronizing on `spec` keeps the underlying EVP_PKEY reachable
        // across both native calls — the Java 8-compatible alternative to
        // Reference.reachabilityFence().
        synchronized (spec)
        {
            int len = rsaServiceNI.getComponent(spec.getReference(), component, null);
            byte[] raw = new byte[len];
            int written = rsaServiceNI.getComponent(spec.getReference(), component, raw);
            return toBigInteger(raw, written, component);
        }
    }

    /**
     * Fetches a component that may legitimately be absent from this key.
     * Returns null only for a plain JO_OPENSSL_ERROR, OpenSSL's "no such param"
     * for a key without CRT data; every other negative is thrown.
     */
    static BigInteger getOptional(RSAServiceNI rsaServiceNI, PKEYKeySpec spec, int component)
    {
        synchronized (spec)
        {
            int len = rsaServiceNI.ni_getComponent(spec.getReference(), component, null);
            if (isAbsent(rsaServiceNI, len))
            {
                return null;
            }
            byte[] raw = new byte[len];
            int written = rsaServiceNI.ni_getComponent(spec.getReference(), component, raw);
            if (isAbsent(rsaServiceNI, written))
            {
                Arrays.clear(raw);
                return null;
            }
            return toBigInteger(raw, written, component);
        }
    }

    /** A plain JO_OPENSSL_ERROR means absent; any other negative goes through the error handler. */
    private static boolean isAbsent(RSAServiceNI rsaServiceNI, int code)
    {
        if (code == ErrorCode.JO_OPENSSL_ERROR.getCode())
        {
            return true;
        }
        rsaServiceNI.handleErrors(code);
        return false;
    }

    /**
     * OSSL hands us a big-endian unsigned magnitude; positive sign forces the BigInteger to interpret it
     * without two's-complement wrapping. Byte copies of a private slot are cleared once it is built.
     */
    private static BigInteger toBigInteger(byte[] raw, int written, int component)
    {
        byte[] bytes = raw;
        if (written != raw.length)
        {
            // Component shrunk between query and fetch - should never happen.
            bytes = new byte[written];
            System.arraycopy(raw, 0, bytes, 0, written);
        }
        try
        {
            return new BigInteger(1, bytes);
        }
        finally
        {
            if (component >= RSAServiceNI.COMP_PRIVATE_EXPONENT)
            {
                Arrays.clear(raw);
                Arrays.clear(bytes);
            }
        }
    }
}
