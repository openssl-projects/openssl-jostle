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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

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
    static BigInteger getRequired(PKEYKeySpec spec, int component)
    {
        // Synchronizing on `spec` keeps the underlying EVP_PKEY reachable
        // across both native calls — the Java 8-compatible alternative to
        // Reference.reachabilityFence().
        synchronized (spec)
        {
            int len = NISelector.RSAServiceNI.getComponent(spec.getReference(), component, null);
            byte[] raw = new byte[len];
            int written = NISelector.RSAServiceNI.getComponent(spec.getReference(), component, raw);
            if (written != raw.length)
            {
                // Component shrunk between query and fetch — should never happen.
                byte[] trimmed = new byte[written];
                System.arraycopy(raw, 0, trimmed, 0, written);
                raw = trimmed;
            }
            // OSSL hands us a big-endian unsigned magnitude; positive sign forces
            // the BigInteger to interpret it without two's-complement wrapping.
            return new BigInteger(1, raw);
        }
    }

    /**
     * Fetches a component that may legitimately be absent from this key.
     * Returns null on any negative return from the native layer (which
     * is OpenSSL signalling "no such param" for a key without CRT data).
     */
    static BigInteger getOptional(PKEYKeySpec spec, int component)
    {
        synchronized (spec)
        {
            int len = NISelector.RSAServiceNI.ni_getComponent(spec.getReference(), component, null);
            if (len < 0)
            {
                return null;
            }
            byte[] raw = new byte[len];
            int written = NISelector.RSAServiceNI.ni_getComponent(spec.getReference(), component, raw);
            if (written < 0)
            {
                return null;
            }
            if (written != raw.length)
            {
                byte[] trimmed = new byte[written];
                System.arraycopy(raw, 0, trimmed, 0, written);
                raw = trimmed;
            }
            return new BigInteger(1, raw);
        }
    }
}
