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

package org.openssl.jostle.jcajce.interfaces;

import java.security.PublicKey;

public interface EdDSAPublicKey extends PublicKey,EdDSAKey
{
    /**
     * Raw RFC 8032 public key bytes — 32 octets for Ed25519, 57 for Ed448.
     *
     * <p>Declared here so a caller holding the interface can reach the key
     * material without an X.509 round-trip. The implementations already had
     * this method; only the interface lacked it, which meant the raw route
     * existed and was unreachable through the published type.
     *
     * <p>Abstract rather than a defaulted no-op: there is no sensible fallback
     * for key material, and a throwing default would let a future key class
     * omit it silently. {@code MLDSAPublicKey} and {@code SLHDSAPublicKey}
     * declare an equivalent (spelled {@code getPublicData()}); the name here
     * follows the existing implementations rather than introducing a second
     * name for the same value.
     */
    byte[] getRawPublic();
}
