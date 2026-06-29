/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.multirelease;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Source-level parity guard for the multi-release native-reference pattern.
 *
 * <p>A class that holds a native handle (a {@code NativeReference}) and makes
 * native calls under {@code synchronized(this)} in the Java 8 baseline
 * ({@code src/main/java}) keeps the handle reachable across the call via the
 * monitor. JDK 9+ replaces that with {@code Reference.reachabilityFence(this)}
 * inside {@code try/finally} in a {@code src/main/javaN/} override (see
 * java-spi.md, "Native references must outlive every JNI/FFI call"). The
 * baseline-only form is still <em>correct</em> -- the monitor keeps {@code this}
 * reachable on JDK 9+ too -- but it silently drifts from every peer SPI, and on
 * JDK 9+ the multi-release jar then serves the monitor-based class instead of
 * the intended fence.
 *
 * <p>The compiler cannot catch a missing override, so this is the guard. For
 * every baseline class that uses {@code synchronized (this)} together with a
 * {@code NativeReference} (or a {@code getReference()} call), it asserts a
 * multi-release override exists at some {@code src/main/javaN/} path and that
 * the override uses {@code reachabilityFence}. It was added after
 * {@code RSAPKCS1CipherSpi}, {@code RSAOAEPCipherSpi} and {@code KSServiceSPI}
 * were each found shipping baseline-only.
 *
 * <p>The check needs the source tree. When the suite is run from a packaged test
 * jar with no sources nearby, there is nothing to analyse, so the test
 * <em>skips</em> (a lint with nothing to lint) rather than failing.
 */
public class NativeReferenceParityTest
{
    // Override source sets, in ascending JDK order. A class first expressible at
    // a higher level (e.g. the EdEC key classes, which implement JDK-15 EdEC
    // interfaces) carries its fence override at that level rather than java9.
    private static final String[] OVERRIDE_DIRS =
            {"java9", "java11", "java15", "java17", "java21", "java25"};

    private static final Pattern SYNCHRONIZED_THIS =
            Pattern.compile("synchronized\\s*\\(\\s*this\\s*\\)");

    @Test
    public void everyNativeReferenceClassHasAFenceOverride()
        throws IOException
    {
        Path mainJava = findMainJava();
        Assumptions.assumeTrue(mainJava != null,
                "src/main/java is not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") -- this guard is a source-level "
                        + "lint, so when the tests run from a packaged test jar with no source "
                        + "tree nearby there is nothing to check and the test is skipped, not failed");

        List<Path> sources;
        try (Stream<Path> walk = Files.walk(mainJava))
        {
            sources = walk.filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());
        }

        List<String> violations = new ArrayList<String>();
        for (Path source : sources)
        {
            String body = read(source);
            if (!SYNCHRONIZED_THIS.matcher(body).find())
            {
                continue;
            }
            if (!body.contains("NativeReference") && !body.contains("getReference()"))
            {
                continue;
            }

            String rel = mainJava.relativize(source).toString();
            if (!hasFenceOverride(mainJava, rel))
            {
                violations.add(rel);
            }
        }

        Assertions.assertTrue(violations.isEmpty(),
                "Baseline classes that hold a native reference under synchronized(this) but lack a "
                        + "javaN/ Reference.reachabilityFence(this) override (see java-spi.md, "
                        + "\"Native references must outlive every JNI/FFI call\"): " + violations);
    }

    private static boolean hasFenceOverride(Path mainJava, String rel)
        throws IOException
    {
        for (String dir : OVERRIDE_DIRS)
        {
            Path twin = mainJava.resolveSibling(dir).resolve(rel);
            if (Files.exists(twin) && read(twin).contains("reachabilityFence"))
            {
                return true;
            }
        }
        return false;
    }

    private static String read(Path path)
        throws IOException
    {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    /**
     * Locate the {@code src/main/java} baseline source root relative to the test
     * working directory (the module dir under Gradle; a repo-root run is also
     * tolerated). Returns {@code null} when no source tree is reachable -- e.g.
     * the tests are being run from a packaged test jar -- so the caller can skip
     * rather than fail: a source-level lint has nothing to analyse there.
     */
    private static Path findMainJava()
    {
        String[] candidates = {"src/main/java", "jostle/src/main/java"};
        for (String candidate : candidates)
        {
            Path path = Paths.get(candidate);
            if (Files.isDirectory(path))
            {
                return path.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
