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

import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

/**
 * A TLS hybrid KEM key (draft-ietf-tls-ecdhe-mlkem).
 *
 * <p>These keys have <b>no ASN.1 encoding</b>. No provider registers an
 * encoder or a decoder for them, so {@code getEncoded()} returns null and
 * {@code getFormat()} returns null on both halves of every variant. That is
 * the JCA-sanctioned way for a key to say "I have no encoding"; it also means
 * these keys cannot be serialized (java.security.KeyRep requires an encoding)
 * and cannot cross a provider boundary the way an encodable key can.
 */
public interface MLXKEMKey extends OSSLKey
{
    /**
     * Return the parameters for this key.
     *
     * @return an MLXKEMParameterSpec
     */
    MLXKEMParameterSpec getParameterSpec();
}
