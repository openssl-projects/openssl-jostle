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
 * Canary for {@code src/test/java21} on the integration leg.
 *
 * <p>That leg filters to {@code *LimitTest*}, {@code *IntegrationTest*} and
 * {@code *OpsTest*}, so {@link SourceSet21CanaryTest} cannot reach it. Keep
 * this trivial and dependency-free; see the canary section of
 * {@code .claude/guides/testing.md}.
 */
public class SourceSet21CanaryIntegrationTest
{
    @Test
    public void thisSourceSetRanOnAJdkOfAtLeastItsOwnLevel()
    {
        int running = Integer.parseInt(System.getProperty("java.specification.version"));
        Assertions.assertTrue(running >= 21,
                "src/test/java21 ran on JDK " + running
                        + "; a source set must only be wired into legs at or above its level");
    }
}
