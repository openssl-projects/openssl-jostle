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

import java.security.spec.KeySpec;

/**
 * PublicKeySpec for the TLS hybrid KEMs.
 *
 * <p>The only importable form for these keys: there is no
 * SubjectPublicKeyInfo encoding, so {@code X509EncodedKeySpec} does not apply.
 * The data is the raw TLS key_exchange share - the ML-KEM encapsulation key
 * and the ECDH public point concatenated, in this group's order (see
 * {@link MLXKEMParameterSpec#isMlkemFirst}).
 *
 * <p>There is deliberately no private counterpart; hybrid private material
 * does not leave the provider.
 */
public class MLXKEMPublicKeySpec
        implements KeySpec
{
    private final MLXKEMParameterSpec params;
    private final byte[] publicData;

    /**
     * @param params     the hybrid group.
     * @param publicData the raw public share.
     */
    public MLXKEMPublicKeySpec(MLXKEMParameterSpec params, byte[] publicData)
    {
        this.params = params;
        this.publicData = Arrays.clone(publicData);
    }

    public MLXKEMParameterSpec getParameterSpec()
    {
        return params;
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicData);
    }
}
