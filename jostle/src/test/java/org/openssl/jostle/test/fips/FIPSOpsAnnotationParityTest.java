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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Source-level parity guard for the FIPS OPS / Limit test discipline.
 *
 * <p>Two testing.md rules govern the {@code *OpsTest} / {@code *LimitTest}
 * classes under {@code .../test/fips} and today are enforced only by manual
 * review, so a copy-pasted FIPS test that keeps a stale annotation or an empty
 * catch body is caught by nobody:
 *
 * <ol>
 *   <li><b>"Pin the exception message in OPS / Limit-test catch blocks"</b> — a
 *   catch block MUST assert something about the exception it caught; an empty
 *   {@code // expected} body (no statements at all) is forbidden.</li>
 *   <li><b>"Link every OPS test to its C-source fault-injection site"</b> — the
 *   FIPS tree drives the {@code interface/fips/} native library, so every
 *   {@code // Exercises} annotation in a FIPS test must name
 *   {@code interface/fips/...}, never {@code interface/nonfips/...}. A FIPS ops
 *   test copied from its non-FIPS sibling that keeps the {@code nonfips}
 *   annotation points a reader at the wrong C source.</li>
 * </ol>
 *
 * <p>The check needs the source tree. When the suite is run from a packaged test
 * jar with no sources nearby, there is nothing to analyse, so the test
 * <em>skips</em> (a lint with nothing to lint) rather than failing — mirroring
 * {@code NativeReferenceParityTest}. It reads {@code .java} files only and needs
 * neither the FIPS module nor {@code TEST_FIPS_LIB}.
 *
 * <p>Scope note: the assertThrows-without-a-message form is deliberately NOT
 * flagged. Legitimate current tests (e.g. an op-mode rejection that only pins
 * the exception TYPE) use a bare {@code assertThrows}, and there is no reliable
 * heuristic that separates those from a lax one, so enforcing it would produce
 * false positives on the clean tree. This guard enforces the two rules that can
 * be checked without false positives: empty catch bodies and the {@code nonfips}
 * annotation prefix.
 */
public class FIPSOpsAnnotationParityTest
{
    private static final String NONFIPS_TREE = "interface/" + "nonfips/";

    private static final Pattern CATCH_HEAD =
            Pattern.compile("catch\\s*\\(([^)]*)\\)\\s*\\{");

    @Test
    public void everyFipsOpsTestPinsMessageAndLinksFipsTree()
        throws IOException
    {
        Path fipsDir = findFipsTestDir();
        Assumptions.assumeTrue(fipsDir != null,
                "the FIPS test source dir is not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") -- this guard is a source-level "
                        + "lint, so when the tests run from a packaged test jar with no source "
                        + "tree nearby there is nothing to check and the test is skipped, not failed");

        List<Path> sources;
        try (Stream<Path> walk = Files.list(fipsDir))
        {
            sources = walk.filter(p -> isOpsOrLimitTest(p))
                    .collect(Collectors.toList());
        }

        List<String> violations = new ArrayList<String>();
        for (Path source : sources)
        {
            String rel = source.getFileName().toString();
            String body = read(source);

            findEmptyCatchBlocks(rel, body, violations);
            findNonFipsAnnotations(rel, body, violations);
        }

        Assertions.assertTrue(violations.isEmpty(),
                "FIPS OPS/Limit tests must pin the exception message/error-code in every catch "
                        + "block (testing.md \"Pin the exception message\") and every // Exercises "
                        + "annotation must name the interface/fips/ tree (testing.md \"Link every OPS "
                        + "test to its C site\"). Offending file:line:\n  "
                        + String.join("\n  ", violations));
    }

    private static boolean isOpsOrLimitTest(Path p)
    {
        String name = p.getFileName().toString();
        return name.endsWith("OpsTest.java") || name.endsWith("LimitTest.java");
    }

    /**
     * Flag any {@code catch (...) { }} whose body, once comments and string/char
     * literals are scrubbed away, is empty. This is exactly the forbidden
     * {@code // expected} empty catch body — a catch that swallows the exception
     * without asserting anything about it.
     */
    private static void findEmptyCatchBlocks(String rel, String body, List<String> violations)
    {
        String scrubbed = scrub(body);
        Matcher m = CATCH_HEAD.matcher(scrubbed);
        while (m.find())
        {
            int open = m.end() - 1; // index of the '{'
            int close = matchBrace(scrubbed, open);
            if (close < 0)
            {
                continue;
            }
            String inner = scrubbed.substring(open + 1, close).trim();
            if (inner.isEmpty())
            {
                int line = lineOf(body, m.start());
                violations.add(rel + ":" + line
                        + " -- catch (" + m.group(1).trim()
                        + ") has an empty body; pin the exception message or error code");
            }
        }
    }

    /**
     * Flag any {@code // Exercises} annotation that references the
     * {@code interface/nonfips/} tree — a FIPS test drives the
     * {@code interface/fips/} native library, so a nonfips annotation is a stale
     * copy-paste from the non-FIPS sibling.
     */
    private static void findNonFipsAnnotations(String rel, String body, List<String> violations)
    {
        String[] lines = body.split("\n", -1);
        for (int i = 0; i < lines.length; i++)
        {
            String line = lines[i];
            if (line.contains("Exercises") && line.contains(NONFIPS_TREE))
            {
                violations.add(rel + ":" + (i + 1)
                        + " -- // Exercises annotation names the nonfips tree; a FIPS test must "
                        + "point at interface/fips/");
            }
        }
    }

    /**
     * Replace every line comment, block comment, and string/char literal with
     * spaces (newlines preserved so line numbers stay accurate). This lets the
     * catch-body and brace matching ignore braces that live inside comments or
     * string literals.
     */
    private static String scrub(String src)
    {
        char[] out = src.toCharArray();
        int n = out.length;
        int i = 0;
        while (i < n)
        {
            char c = out[i];
            if (c == '/' && i + 1 < n && out[i + 1] == '/')
            {
                while (i < n && out[i] != '\n')
                {
                    out[i] = ' ';
                    i++;
                }
            }
            else if (c == '/' && i + 1 < n && out[i + 1] == '*')
            {
                out[i] = ' ';
                out[i + 1] = ' ';
                i += 2;
                while (i < n && !(out[i] == '*' && i + 1 < n && out[i + 1] == '/'))
                {
                    if (out[i] != '\n')
                    {
                        out[i] = ' ';
                    }
                    i++;
                }
                if (i + 1 < n)
                {
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                }
            }
            else if (c == '"' || c == '\'')
            {
                char quote = c;
                out[i] = ' ';
                i++;
                while (i < n && out[i] != quote)
                {
                    if (out[i] == '\\' && i + 1 < n)
                    {
                        out[i] = ' ';
                        out[i + 1] = ' ';
                        i += 2;
                    }
                    else
                    {
                        if (out[i] != '\n')
                        {
                            out[i] = ' ';
                        }
                        i++;
                    }
                }
                if (i < n)
                {
                    out[i] = ' ';
                    i++;
                }
            }
            else
            {
                i++;
            }
        }
        return new String(out);
    }

    /**
     * Given the index of an opening brace, return the index of its matching
     * closing brace, or -1 if unbalanced. Operates on already-scrubbed source so
     * braces inside comments/strings are gone.
     */
    private static int matchBrace(String s, int open)
    {
        int depth = 0;
        for (int i = open; i < s.length(); i++)
        {
            char c = s.charAt(i);
            if (c == '{')
            {
                depth++;
            }
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }
        return -1;
    }

    private static int lineOf(String src, int index)
    {
        int line = 1;
        for (int i = 0; i < index && i < src.length(); i++)
        {
            if (src.charAt(i) == '\n')
            {
                line++;
            }
        }
        return line;
    }

    private static String read(Path path)
        throws IOException
    {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    /**
     * Locate the {@code .../test/fips} source dir relative to the test working
     * directory (the module dir under Gradle; a repo-root run is also tolerated),
     * mirroring {@code NativeReferenceParityTest.findMainJava}. Returns
     * {@code null} when no source tree is reachable -- e.g. the tests are being
     * run from a packaged test jar -- so the caller can skip rather than fail.
     */
    private static Path findFipsTestDir()
    {
        String[] candidates = {"src/test/java", "jostle/src/test/java"};
        String pkg = "org/openssl/jostle/test/fips";
        for (String candidate : candidates)
        {
            Path path = Paths.get(candidate).resolve(pkg);
            if (Files.isDirectory(path))
            {
                return path.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
