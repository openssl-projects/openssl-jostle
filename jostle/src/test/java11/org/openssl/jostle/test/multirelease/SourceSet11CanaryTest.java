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

package org.openssl.jostle.test.multirelease;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Canary for the {@code src/test/java11} source set: proves the wiring RUNS it.
 *
 * <p>Companion to {@code SourceSet17CanaryTest} and
 * {@code SourceSet21CanaryTest}. This one was MISSING: java17 and java21 had
 * canaries while java11 and java25 did not, so {@code unitTest11} and
 * {@code unitTest25*} were the two legs whose wiring nothing proved. java11 was
 * the dangerous one — it held a single test file, and MT-60's measured lesson is
 * that swapping one single-file source set for another CONSERVES the result
 * count (193 either way), so only a by-NAME check separates them.
 *
 * <p>Keep it trivial and dependency-free, per the guides: a canary that can fail
 * for its own reasons stops being a wiring signal.
 */
public class SourceSet11CanaryTest
{
    @Test
    public void thisSourceSetRanOnAJdkOfAtLeastItsOwnLevel()
    {
        int running = Integer.parseInt(System.getProperty("java.specification.version"));
        Assertions.assertTrue(running >= 11,
                "src/test/java11 ran on JDK " + running
                        + "; a source set must only be wired into legs at or above its level");
    }
}
