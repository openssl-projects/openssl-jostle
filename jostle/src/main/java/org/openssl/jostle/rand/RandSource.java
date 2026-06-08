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

package org.openssl.jostle.rand;

import java.security.SecureRandom;

public interface RandSource
{
    int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant);

    SecureRandom getRandom();

    /**
     * Reported security strength in bits of the underlying randomness
     * source, or {@code 0} if the strength cannot be determined.
     *
     * <p>On Java 9+ a {@link SecureRandom} constructed with explicit
     * {@code DrbgParameters} reports its instantiated strength here.
     * Implementations that wrap a plain {@code SecureRandom} (no
     * {@code DrbgParameters}) — or the Java 8 baseline which lacks the
     * {@code DrbgParameters} API entirely — return {@code 0}, meaning
     * "unknown / unverified".
     *
     * <p>Used by {@link DefaultRandSource#replaceWith(RandSource, SecureRandom, int)}
     * to decide whether the existing source already satisfies a
     * strength requirement without constructing a new instance.
     */
    int getStrength();
}
