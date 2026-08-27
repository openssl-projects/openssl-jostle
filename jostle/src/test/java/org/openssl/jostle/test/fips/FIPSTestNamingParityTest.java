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
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Source-level parity guard: a test class whose CODE touches the JSLFIPS
 * provider must be FIPS-named.
 *
 * <p>This exists to make a name filter SOUND. The FIPS module-configuration
 * sweep runs the suite once per {@code fipsmodule.cnf} configuration, and a
 * {@code fipsmodule.cnf} switch can only change the behaviour of the FIPS
 * module — which only JSLFIPS touches. Re-running the other ~150 test classes
 * per configuration is pure cost, so the sweep selects classes by name. That
 * selection is only safe while every FIPS-touching class is discoverable by
 * name; a single mis-named one drops out of every configuration silently, and
 * a fast sweep that quietly stops covering something is worse than a slow one
 * that covers everything.
 *
 * <p><b>Comments are stripped before matching, and that is load-bearing.</b>
 * Javadoc explaining a FIPS boundary reads identically to code crossing it:
 * {@code KDFAgreementTest} and {@code DHAlgorithmParametersRecursionTest} both
 * describe the FIPS split in prose while containing zero FIPS references in
 * code. A raw-text scan flags both, which is the same false-positive
 * {@code FIPSLibraryLookupParityTest} hit when its first version matched
 * Javadoc that explained why NOT to use {@code loaderLookup}. Strip first,
 * then match.
 *
 * <p>Like its sibling guards this is a lint over source text: it needs no FIPS
 * module, runs everywhere, and skips only when the source tree is unreachable
 * (running from a packaged test jar).
 */
public class FIPSTestNamingParityTest
{
    /**
     * Tokens that mean "this class drives the FIPS provider". Deliberately the
     * production types and the FIPS test helper, not the string "fips" — the
     * latter appears in ordinary prose and in base-provider algorithm names.
     */
    private static final String[] FIPS_CODE_TOKENS = {
            "JostleFIPSProvider",
            "FIPSNISelector",
            "FIPSTestUtil",
            "assumeFipsProvider",
            "addFipsProvider",
            "skipFipsTests",
            "OpenSSLFIPSNI",
            "\"JSLFIPS\"",
    };

    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");

    /**
     * The whole point of the guard: a class the sweep's name filter would
     * select. Anything containing "FIPS" qualifies, wherever it lives —
     * {@code FIPSLibraryLookupParityTest} sits under {@code test/multirelease}
     * and is still selected.
     */
    private static boolean isFipsNamed(String fileName)
    {
        return fileName.contains("FIPS");
    }

    @Test
    public void everyFipsTouchingTestClassIsFipsNamed()
    {
        List<Path> roots = testSourceRoots();
        Assumptions.assumeFalse(roots.isEmpty(),
                "no test source root is reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") — this guard is a source-level "
                        + "lint, so with no source tree nearby there is nothing to check and the "
                        + "test is skipped, not failed");

        List<String> violations = new ArrayList<String>();
        int checked = 0;
        int fipsTouching = 0;

        for (Path root : roots)
        {
            for (Path source : javaSourcesUnder(root))
            {
                String name = source.getFileName().toString();
                if (!name.endsWith("Test.java"))
                {
                    continue;
                }

                String body = read(source);
                if (!body.contains("@Test"))
                {
                    continue;
                }
                checked++;

                if (!touchesFipsInCode(body))
                {
                    continue;
                }
                fipsTouching++;

                if (!isFipsNamed(name))
                {
                    violations.add(root.relativize(source).toString());
                }
            }
        }

        Assertions.assertTrue(checked > 50,
                "only " + checked + " test classes were scanned — the guard is not looking where "
                        + "it thinks, and would pass vacuously");
        Assertions.assertTrue(fipsTouching > 20,
                "only " + fipsTouching + " FIPS-touching classes found — the token list has "
                        + "probably drifted from how these tests reach the provider");

        Assertions.assertTrue(violations.isEmpty(),
                "these test classes drive the JSLFIPS provider but are not FIPS-named, so the "
                        + "module-configuration sweep's name filter would silently skip them:\n  "
                        + String.join("\n  ", violations)
                        + "\nSplit the FIPS-touching tests into their own FIPS<Family>Test class "
                        + "under test/fips/ (see FIPSKDFAgreementTest alongside KDFAgreementTest "
                        + "for the shape). Do NOT simply rename a mixed class — the base-provider "
                        + "half must keep running outside the sweep.");
    }

    /** True when a FIPS token survives comment stripping. */
    private static boolean touchesFipsInCode(String body)
    {
        String code = LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
        for (String token : FIPS_CODE_TOKENS)
        {
            if (code.contains(token))
            {
                return true;
            }
        }
        return false;
    }

    private static List<Path> testSourceRoots()
    {
        String[] candidates = {"src/test/java", "jostle/src/test/java",
                "src/test/java25", "jostle/src/test/java25"};
        List<Path> found = new ArrayList<Path>();
        for (String candidate : candidates)
        {
            Path path = Paths.get(candidate);
            if (Files.isDirectory(path))
            {
                found.add(path.toAbsolutePath().normalize());
            }
        }
        return found;
    }

    private static List<Path> javaSourcesUnder(Path root)
    {
        final List<Path> out = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> walk = Files.walk(root))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(".java")).forEach(out::add);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    private static String read(Path path)
    {
        try
        {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }
}
