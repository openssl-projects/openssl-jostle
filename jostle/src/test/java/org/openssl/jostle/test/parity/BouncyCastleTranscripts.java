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

package org.openssl.jostle.test.parity;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * BouncyCastle behaviour TRANSCRIBED from a measurement, in one place.
 *
 * <p>A pin should hold a literal: re-measuring BouncyCastle inside a pin would
 * make the pin follow BC wherever it went, which is the opposite of pinning.
 * The risk a literal carries is that a bcprov bump moves the reference with
 * nothing failing.
 *
 * <p>So the literal lives here ONCE and has two consumers: the pin asserts our
 * behaviour against it, and the drift check measures LIVE BouncyCastle against
 * it. A second copy would let the two drift apart independently, which is the
 * failure this consolidation exists to prevent - the same shape as any other
 * value with two sources of truth.
 *
 * <p>Measured 2026-08-31 against bcprov-jdk18on 1.85.2.
 */
public final class BouncyCastleTranscripts
{
    private BouncyCastleTranscripts()
    {
    }

    /** AESWRAP wrap lengths BouncyCastle refuses, and the type it uses. */
    public static final int[] KW_WRAP_ILLEGAL = {0, 1, 7, 15, 23, 31};
    public static final Class<? extends Exception> KW_WRAP_TYPE = IllegalBlockSizeException.class;

    /** AESWRAP unwrap lengths BouncyCastle refuses. */
    public static final int[] KW_UNWRAP_ILLEGAL = {0, 1, 7, 8, 15, 16, 23, 31};
    public static final Class<? extends Exception> KW_UNWRAP_TYPE = BadPaddingException.class;

    /** AESWRAPPAD unwrap lengths BouncyCastle refuses. */
    public static final int[] KWP_UNWRAP_ILLEGAL = {0, 1, 7, 8, 15, 23, 31};
    public static final Class<? extends Exception> KWP_UNWRAP_TYPE = BadPaddingException.class;

    /**
     * The type BouncyCastle raises when an AESGMAC instance is reused after
     * {@code doFinal} — a refusal we deliberately do NOT make (MT-44).
     *
     * <p>Transcribed rather than re-measured inside the pin: a pin that read
     * BouncyCastle live would follow it wherever it went, which is the opposite
     * of pinning. {@code BouncyCastleDriftTest} measures the live value against
     * this constant, so a bcprov change is noticed instead of absorbed.
     */
    public static final Class<? extends Exception> GMAC_REUSE_REFUSAL_TYPE = IllegalStateException.class;

    /** Zero is the only illegal KWP wrap length (RFC 5649 accepts >= 1). */
    public static final int[] KWP_WRAP_ILLEGAL = {0};
    public static final Class<? extends Exception> KWP_WRAP_TYPE = IllegalBlockSizeException.class;
}
