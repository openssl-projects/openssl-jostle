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
import java.security.spec.KeySpec;

/**
 * Parameters for the RFC 4253 section 7.2 SSH key derivation (OpenSSL's
 * {@code SSHKDF}), as served by
 * {@code SecretKeyFactory.getInstance("SSHKDF-SHA256")} and its siblings. The
 * digest is fixed by the registered algorithm name and must be the one the
 * key exchange itself used.
 *
 * <p>Every input is mandatory. Unlike a salt or an info string, the shared
 * secret K, the exchange hash H and the session id have no defined "absent"
 * form in RFC 4253, so a null is a caller error rather than a request for a
 * default.</p>
 *
 * <p>The shared secret K is the {@code mpint} encoding from the key exchange,
 * not the raw group element — that is what RFC 4253 hashes, and what the NIST
 * CAVS vectors carry.</p>
 */
public class SSHKDFParameterSpec
    implements KeySpec, AlgorithmParameterSpec
{
    /**
     * Which of the six RFC 4253 section 7.2 keys to derive. The single-letter
     * codes are the ones the RFC and OpenSSL both use; all six are accepted by
     * every supported OpenSSL build and produce pairwise-distinct output.
     */
    public enum KeyType
    {
        /** "A" — initial IV, client to server. */
        INITIAL_IV_CLIENT_TO_SERVER("A"),
        /** "B" — initial IV, server to client. */
        INITIAL_IV_SERVER_TO_CLIENT("B"),
        /** "C" — encryption key, client to server. */
        ENCRYPTION_KEY_CLIENT_TO_SERVER("C"),
        /** "D" — encryption key, server to client. */
        ENCRYPTION_KEY_SERVER_TO_CLIENT("D"),
        /** "E" — integrity key, client to server. */
        INTEGRITY_KEY_CLIENT_TO_SERVER("E"),
        /** "F" — integrity key, server to client. */
        INTEGRITY_KEY_SERVER_TO_CLIENT("F");

        private final String code;

        KeyType(String code)
        {
            this.code = code;
        }

        /**
         * @return the single-letter {@code OSSL_KDF_PARAM_SSHKDF_TYPE} code.
         */
        public String getCode()
        {
            return code;
        }
    }

    private final byte[] sharedSecret;
    private final byte[] exchangeHash;
    private final byte[] sessionId;
    private final KeyType type;
    private final int outputLength;

    /**
     * @param sharedSecret the shared secret K, mpint-encoded. Must not be null.
     * @param exchangeHash the exchange hash H. Must not be null.
     * @param sessionId    the session id. Must not be null.
     * @param type         which of the six keys to derive. Must not be null.
     * @param outputLength derived key length in bytes. Must be positive.
     */
    public SSHKDFParameterSpec(byte[] sharedSecret, byte[] exchangeHash, byte[] sessionId,
                               KeyType type, int outputLength)
    {
        if (sharedSecret == null)
        {
            throw new IllegalArgumentException("shared secret is null");
        }

        if (exchangeHash == null)
        {
            throw new IllegalArgumentException("exchange hash is null");
        }

        if (sessionId == null)
        {
            throw new IllegalArgumentException("session id is null");
        }

        if (type == null)
        {
            throw new IllegalArgumentException("type is null");
        }

        // SSHKDF is the KDF that makes this check load-bearing rather than
        // belt-and-braces: it accepts a zero-length request and emits a
        // zero-length key on every supported OpenSSL build.
        if (outputLength <= 0)
        {
            throw new IllegalArgumentException("output length must be positive");
        }

        this.sharedSecret = Arrays.clone(sharedSecret);
        this.exchangeHash = Arrays.clone(exchangeHash);
        this.sessionId = Arrays.clone(sessionId);
        this.type = type;
        this.outputLength = outputLength;
    }

    /**
     * @return a copy of the shared secret K.
     */
    public byte[] getSharedSecret()
    {
        return Arrays.clone(sharedSecret);
    }

    /**
     * @return a copy of the exchange hash H.
     */
    public byte[] getExchangeHash()
    {
        return Arrays.clone(exchangeHash);
    }

    /**
     * @return a copy of the session id.
     */
    public byte[] getSessionId()
    {
        return Arrays.clone(sessionId);
    }

    public KeyType getType()
    {
        return type;
    }

    /**
     * @return the derived key length in bytes.
     */
    public int getOutputLength()
    {
        return outputLength;
    }
}
