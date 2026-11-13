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
 * Parameters for RFC 8439 ChaCha20 ("ChaCha20" on JSL): a 12-byte nonce and the initial value of the 32-bit block
 * counter.
 *
 * <p>The counterpart of the JDK's {@code javax.crypto.spec.ChaCha20ParameterSpec}, which exists only from Java 11,
 * and of BouncyCastle's {@code BCChaCha20ParameterSpec}: same values, same meaning, and JSL accepts this one on
 * every Java version. Starting at a given block is what DTLS 1.3 record number protection (RFC 9147 4.2.3) needs.
 *
 * <p>The counter is unsigned and carried in an {@code int}: a negative value addresses one of the blocks from
 * 2^31 to 2^32 - 1. The cipher returns to this block after each {@code doFinal}, refuses a request that would pass
 * block 2^32 - 1 (the RFC 8439 per-nonce limit), and returns {@code null} from {@code getParameters()}.
 */
public class ChaCha20CounterParameterSpec
    implements AlgorithmParameterSpec
{
    private static final int NONCE_LENGTH = 12;

    private final byte[] nonce;
    private final int counter;

    /**
     * @param nonce   the 12-byte nonce.
     * @param counter the initial block counter, an unsigned 32-bit value.
     * @throws NullPointerException     if nonce is null.
     * @throws IllegalArgumentException if nonce is not 12 bytes long.
     */
    public ChaCha20CounterParameterSpec(byte[] nonce, int counter)
    {
        if (nonce == null)
        {
            throw new NullPointerException("nonce cannot be null");
        }
        if (nonce.length != NONCE_LENGTH)
        {
            throw new IllegalArgumentException("nonce must be " + NONCE_LENGTH + " bytes long");
        }
        this.nonce = Arrays.clone(nonce);
        this.counter = counter;
    }

    /**
     * @return a copy of the 12-byte nonce.
     */
    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    /**
     * @return the initial block counter, an unsigned 32-bit value.
     */
    public int getCounter()
    {
        return counter;
    }
}
