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
 * Canary for the {@code src/test/java17} source set: proves the wiring RUNS it.
 *
 * <h2>Why a canary and not a comment</h2>
 *
 * <p>MT-60: {@code unitTest21} was wired to the {@code test17} source set, so a
 * JDK-21-only unit test would have compiled, run under
 * {@code integrationTest21}, and silently NOT run under {@code unitTest21}.
 * Nothing failed, because <b>a test that never runs is indistinguishable from a
 * test that passes</b>. Reading the build file is how the mistake survived; only
 * something that must EXECUTE can prove the wiring.
 *
 * <p>So this asserts almost nothing about the code under test. Its whole job is
 * to appear in the results of every leg that claims to include this source set,
 * and the gate's expected-count check names it when it does not — the
 * known-answer control, applied to build wiring rather than to crypto.
 *
 * <p>Keep it trivial and dependency-free. A canary that can fail for its own
 * reasons stops being a wiring signal.
 */
public class SourceSet17CanaryTest
{
    @Test
    public void thisSourceSetRanOnAJdkOfAtLeastItsOwnLevel()
    {
        int running = Integer.parseInt(System.getProperty("java.specification.version"));
        Assertions.assertTrue(running >= 17,
                "src/test/java17 ran on JDK " + running
                        + "; a source set must only be wired into legs at or above its level");
    }
}
