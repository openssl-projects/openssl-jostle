/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level parity guard: every FIPS test class must apply its
 * {@code TEST_FIPS_LIB} skip gate in a {@code @BeforeAll} / {@code @BeforeEach},
 * not per test method.
 *
 * <p>Per-method gating fails OPEN. One test added without the call reaches the
 * JSLFIPS provider on a machine with no module and throws
 * {@code NoSuchProviderException: no such provider: JSLFIPS} instead of
 * skipping. That is not a local failure — {@code TEST_FIPS_LIB} is typically set
 * on a developer machine, so every FIPS test runs and the omission is invisible.
 * It surfaces only in CI, where the ordinary (non-FIPS) jobs run without the
 * variable, and it fails EVERY one of them. That happened once, from a single
 * missing line in a file whose other eleven tests all had it.
 *
 * <p>A class-level gate fails CLOSED: a test added later inherits it with no
 * action by the author, which is the only form that survives future edits.
 *
 * <p>This is a lint over source text, so it needs no FIPS module and must run
 * everywhere. It skips only when the source tree is not reachable (running from
 * a packaged test jar), the same contract as
 * {@code FIPSOpsAnnotationParityTest} and {@code NativeReferenceParityTest}.
 */
public class FIPSTestGateParityTest
{
    /**
     * Tokens that constitute the skip gate. {@code assumeFipsProvider} is the
     * common form; {@code skipFipsTests} is the underlying predicate used
     * directly by a few classes.
     */
    private static final String[] GATE_TOKENS = {"assumeFipsProvider", "skipFipsTests"};

    /**
     * Classes deliberately NOT gated at class level, each for a reason recorded
     * in its own class Javadoc. Keep this list short and justified — an entry
     * added to silence a failure rather than to record a design decision defeats
     * the guard.
     *
     * <ol>
     *   <li>{@code FIPSProviderRandomPropertyIntegrationTest} is mixed by
     *       design: two of its tests read a property through a probe JVM and
     *       need no module, so they must keep running when TEST_FIPS_LIB is
     *       unset. A class-level gate would delete that coverage.</li>
     *   <li>{@code FIPSOpsAnnotationParityTest} is a source lint like this one —
     *       it needs no module at all, and gates on source-tree reachability
     *       instead.</li>
     * </ol>
     */
    private static final Set<String> EXEMPT = new HashSet<String>(Arrays.asList(
            "FIPSProviderRandomPropertyIntegrationTest.java",
            "FIPSOpsAnnotationParityTest.java",
            "FIPSTestGateParityTest.java"));

    private static final Pattern BEFORE_HOOK = Pattern.compile("@Before(?:All|Each)\\b");

    /** A method declaration: captures the name, positioned at its opening brace. */
    private static final Pattern METHOD =
            Pattern.compile("\\b(\\w+)\\s*\\([^)]*\\)\\s*(?:throws [\\w., \\n]+?)?\\s*\\{");

    @Test
    public void everyFipsTestClassGatesAtClassLevel()
        throws IOException
    {
        List<Path> roots = fipsTestDirs();
        Assumptions.assumeFalse(roots.isEmpty(),
                "no FIPS test source dir is reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") -- this guard is a source-level "
                        + "lint, so when the tests run from a packaged test jar with no source "
                        + "tree nearby there is nothing to check and the test is skipped, not failed");

        List<String> violations = new ArrayList<String>();
        int checked = 0;

        for (Path root : roots)
        {
            List<Path> sources = new ArrayList<Path>();
            try (java.util.stream.Stream<Path> list = Files.list(root))
            {
                list.filter(p -> p.getFileName().toString().endsWith(".java")).forEach(sources::add);
            }

            for (Path source : sources)
            {
                String name = source.getFileName().toString();
                if (EXEMPT.contains(name))
                {
                    continue;
                }

                String body = read(source);
                if (!body.contains("@Test"))
                {
                    continue;
                }

                checked++;
                if (!gatesAtClassLevel(body))
                {
                    violations.add(name);
                }
            }
        }

        Assertions.assertTrue(checked > 0, "found no FIPS test classes to check -- the guard is not looking where it thinks");
        Assertions.assertTrue(violations.isEmpty(),
                "these FIPS test classes gate TEST_FIPS_LIB per test method (fails open) instead of in a "
                        + "@BeforeAll/@BeforeEach (fails closed). Move the gate into a before-hook; see "
                        + "FIPSX509CertificateFactoryTest for the shape. If a class legitimately needs "
                        + "tests that run WITHOUT a module, document why in its class Javadoc and add it "
                        + "to EXEMPT: " + violations);
    }

    /**
     * True when some {@code @BeforeAll} / {@code @BeforeEach} body applies a gate
     * directly, or calls a method in the same file that does. One level of
     * indirection covers the {@code before() -> ensureProviders()} shape used
     * across the package.
     */
    private static boolean gatesAtClassLevel(String src)
    {
        Set<String> gatingMethods = new HashSet<String>();
        Matcher m = METHOD.matcher(src);
        while (m.find())
        {
            String body = balancedBlock(src, m.end() - 1);
            if (containsGate(body))
            {
                gatingMethods.add(m.group(1));
            }
        }

        Matcher hook = BEFORE_HOOK.matcher(src);
        while (hook.find())
        {
            int brace = src.indexOf('{', hook.end());
            if (brace < 0)
            {
                continue;
            }
            String body = balancedBlock(src, brace);
            if (containsGate(body) || callsAny(body, gatingMethods))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean containsGate(String body)
    {
        for (String token : GATE_TOKENS)
        {
            if (body.contains(token))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean callsAny(String body, Set<String> methods)
    {
        for (String name : methods)
        {
            if (Pattern.compile("\\b" + Pattern.quote(name) + "\\s*\\(").matcher(body).find())
            {
                return true;
            }
        }
        return false;
    }

    /** The brace-balanced text starting at {@code open}, which must index a '{'. */
    private static String balancedBlock(String src, int open)
    {
        int depth = 0;
        for (int i = open; i < src.length(); i++)
        {
            char c = src.charAt(i);
            if (c == '{')
            {
                depth++;
            }
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return src.substring(open, i + 1);
                }
            }
        }
        return src.substring(open);
    }

    /**
     * Both FIPS test source dirs — the Java 8 baseline and the Java 25 override
     * tree. Either layout (module dir or repo root) is tolerated so the guard
     * works whichever directory Gradle runs from.
     */
    private static List<Path> fipsTestDirs()
    {
        String pkg = "org/openssl/jostle/test/fips";
        String[] candidates = {"src/test/java", "jostle/src/test/java",
                "src/test/java25", "jostle/src/test/java25"};
        List<Path> found = new ArrayList<Path>();
        for (String candidate : candidates)
        {
            Path path = Paths.get(candidate).resolve(pkg);
            if (Files.isDirectory(path))
            {
                found.add(path.toAbsolutePath().normalize());
            }
        }
        return found;
    }

    private static String read(Path path)
        throws IOException
    {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }
}
