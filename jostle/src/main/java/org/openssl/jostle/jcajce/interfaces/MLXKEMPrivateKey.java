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

import java.security.PrivateKey;

/**
 * A hybrid KEM private key.
 *
 * <p>Deliberately has no raw private getter, on any variant. The provider
 * releases the private material for the X25519 / X448 hybrids and refuses it
 * for the SecP ones, so a getter here would work on half the family and throw
 * on the other half - a worse contract than not offering it at all. Private
 * key material stays inside the provider.
 */
public interface MLXKEMPrivateKey
        extends PrivateKey, MLXKEMKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a hybrid KEM public key.
     */
    MLXKEMPublicKey getPublicKey();
}
