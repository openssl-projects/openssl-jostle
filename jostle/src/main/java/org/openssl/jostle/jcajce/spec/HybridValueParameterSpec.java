/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Wraps a base {@link AlgorithmParameterSpec} with an extra value {@code T}
 * that a KDF-bearing key agreement splices onto the raw agreed secret before
 * running the KDF — RFC 9580 §5.1.6/§5.1.7's v6 ECDH construction, where
 * {@code T} is the concatenation of the ephemeral and recipient public keys
 * and the KDF's input is {@code T || Z}.
 *
 * <p>Mirrors {@code org.bouncycastle.jcajce.spec.HybridValueParameterSpec}
 * for caller familiarity, but it is a DIFFERENT class — same reasoning as
 * {@link DHDomainParameterSpec}'s own javadoc.
 *
 * <p>Unlike BC's class, this one does not implement {@code Destroyable} —
 * {@code T} is public key material (an ephemeral and a recipient public
 * key), not a secret.
 */
public class HybridValueParameterSpec implements AlgorithmParameterSpec
{
    private final byte[] t;
    private final boolean prependT;
    private final AlgorithmParameterSpec baseSpec;

    /** As {@link #HybridValueParameterSpec(byte[], boolean, AlgorithmParameterSpec)}, with {@code T} appended, not prepended. */
    public HybridValueParameterSpec(byte[] t, AlgorithmParameterSpec baseSpec)
    {
        this(t, false, baseSpec);
    }

    public HybridValueParameterSpec(byte[] t, boolean prependT, AlgorithmParameterSpec baseSpec)
    {
        this.t = Arrays.clone(t);
        this.prependT = prependT;
        this.baseSpec = baseSpec;
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }

    public boolean isPrependedT()
    {
        return prependT;
    }

    public AlgorithmParameterSpec getBaseParameterSpec()
    {
        return baseSpec;
    }
}
