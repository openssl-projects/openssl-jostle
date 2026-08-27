/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.interfaces;

import java.security.PublicKey;

public interface MLXKEMPublicKey
        extends PublicKey, MLXKEMKey
{
    /**
     * Return the raw public share: the ML-KEM encapsulation key and the ECDH
     * public point concatenated, in the order the TLS key_exchange field uses
     * for this group. The ML-KEM half comes first for the X25519 / X448
     * variants and second for the SecP ones - see
     * {@link org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec#isMlkemFirst}.
     *
     * <p>This is the only way to get a hybrid public key out of this provider;
     * there is no SubjectPublicKeyInfo form.
     *
     * @return the raw public share.
     */
    byte[] getPublicData();
}
