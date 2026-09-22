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
import java.util.stream.Stream;

/**
 * Source-level guard: the FIPS tree relaxes the approved-mode property at
 * exactly ONE site, and that site is the operations-test entropy hook.
 *
 * <p>The FIPS lib ctx pins {@code fips=yes} as its default property query, and
 * that pin is the approved-mode gate for the whole context. A fetch carrying
 * {@code "-fips"} steps around it for one object. There is exactly one place
 * that is sanctioned: {@code rand_ctx_create_test}, which reaches TEST-RAND --
 * shipped inside the validated module, flagged unapproved -- to prime a DRBG
 * with fixed entropy for a known-answer vector. That code exists only in a
 * {@code JOSTLE_OPS} build, so a released library contains no such fetch.
 *
 * <p>A second one appearing anywhere under {@code interface/fips} would be a
 * second hole in the same gate, and it would be invisible at runtime: the
 * fetch succeeds and the operation produces correct-looking output from an
 * unapproved implementation. Nothing behavioural can see it, which is why this
 * is a source lint rather than a test.
 *
 * <p>This is a lint over source text, so it needs no FIPS module and must run
 * everywhere; it skips only when the source tree is unreachable, the same
 * contract as {@code FIPSLibraryLookupParityTest}.
 */
public class FIPSRelaxedPropertyParityTest
{
    private static final String FIPS_TREE = "interface/fips";

    /**
     * The property query as it appears as a whole argument, quotes included.
     * Matching the bare characters would fire on a message such as
     * {@code "cannot fetch with -fips"}, which relaxes nothing; matching the
     * quoted literal is what distinguishes the argument from prose about it.
     */
    private static final String RELAXED_LITERAL = "\"-fips\"";

    /** The one sanctioned site: file, and the function it must sit in. */
    private static final String EXPECTED_FILE = "rand.c";
    private static final String EXPECTED_FUNCTION = "ops_test_rand_ctx";

    /**
     * A scan that reads nothing reports "exactly one occurrence" just as
     * readily as a correct one does, so the file count carries its own floor.
     * The FIPS tree has far more than this; the number only has to be too
     * large for an empty or misrooted walk to reach.
     */
    private static final int MIN_C_FILES = 20;

    @Test
    public void theApprovedModeGateIsRelaxedAtExactlyOneSite() throws IOException
    {
        Path tree = resolveFipsTree();
        Assumptions.assumeTrue(tree != null,
                "interface/fips not reachable from " + Paths.get("").toAbsolutePath());

        List<Path> sources = new ArrayList<Path>();
        try (Stream<Path> walk = Files.walk(tree))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(".c")
                    || p.getFileName().toString().endsWith(".h")).forEach(sources::add);
        }

        Assertions.assertTrue(sources.size() >= MIN_C_FILES,
                "only " + sources.size() + " C sources found under " + tree.toAbsolutePath()
                        + ", which is fewer than a correct walk can reach -- this scan is not"
                        + " reading the tree it reports on");

        List<String> sites = new ArrayList<String>();
        for (Path source : sources)
        {
            String text = stripComments(read(source));
            String[] lines = text.split("\n", -1);
            for (int i = 0; i < lines.length; i++)
            {
                if (lines[i].contains(RELAXED_LITERAL))
                {
                    sites.add(source.getFileName() + ":" + (i + 1) + "  " + lines[i].trim());
                }
            }
        }

        Assertions.assertEquals(1, sites.size(),
                "the FIPS tree must relax fips=yes at exactly one site, the operations-test"
                        + " entropy hook. Found " + sites.size() + ":\n  "
                        + String.join("\n  ", sites));
        Assertions.assertTrue(sites.get(0).startsWith(EXPECTED_FILE + ":"),
                "the one relaxed fetch has moved out of " + EXPECTED_FILE + ": " + sites.get(0));

        // Inside the hook's BODY, not merely later in the file: "after the
        // function starts" is satisfied by a fetch anywhere below it, which
        // includes every production function that follows.
        Path randC = tree.resolve("util").resolve(EXPECTED_FILE);
        String[] body = stripComments(read(randC)).split("\n", -1);

        int open = -1;
        for (int i = 0; i < body.length; i++)
        {
            if (body[i].contains(EXPECTED_FUNCTION) && body[i].contains("("))
            {
                open = i;
                break;
            }
        }
        Assertions.assertTrue(open >= 0,
                EXPECTED_FUNCTION + " is gone from " + EXPECTED_FILE
                        + "; this guard no longer knows where the sanctioned site is");

        // The body ends at the next line that is exactly a closing brace at
        // column 0, which is this file's function-terminator convention.
        int close = -1;
        for (int i = open + 1; i < body.length; i++)
        {
            if ("}".equals(body[i]))
            {
                close = i;
                break;
            }
        }
        Assertions.assertTrue(close > open,
                "cannot find the end of " + EXPECTED_FUNCTION + " from line " + (open + 1));

        int inside = 0;
        int outside = 0;
        for (int i = 0; i < body.length; i++)
        {
            if (!body[i].contains(RELAXED_LITERAL))
            {
                continue;
            }
            if (i >= open && i <= close)
            {
                inside++;
            }
            else
            {
                outside++;
            }
        }
        Assertions.assertEquals(1, inside,
                "expected exactly one relaxed fetch inside " + EXPECTED_FUNCTION
                        + " (lines " + (open + 1) + ".." + (close + 1) + "), found " + inside);
        Assertions.assertEquals(0, outside,
                "a relaxed fetch appears in " + EXPECTED_FILE + " OUTSIDE "
                        + EXPECTED_FUNCTION + ", which is a production path");
    }

    /**
     * Comments go first: a banner explaining why the gate matters reads exactly
     * like a fetch that relaxes it, and the precedent lints were all written
     * twice for that reason.
     *
     * <p>String literals are deliberately KEPT. The thing being located IS a
     * literal, so stripping them would leave this scan matching nothing and
     * reporting it as zero sanctioned sites. What separates the argument from
     * an error message mentioning the property is the quoted form, not the
     * absence of quoting -- see {@link #RELAXED_LITERAL}.
     */
    private static String stripComments(String source)
    {
        StringBuilder out = new StringBuilder(source.length());
        int i = 0;
        while (i < source.length())
        {
            char c = source.charAt(i);
            if (c == '/' && i + 1 < source.length() && source.charAt(i + 1) == '*')
            {
                int end = source.indexOf("*/", i + 2);
                int stop = end < 0 ? source.length() : end + 2;
                for (int k = i; k < stop; k++)
                {
                    out.append(source.charAt(k) == '\n' ? '\n' : ' ');
                }
                i = stop;
            }
            else if (c == '/' && i + 1 < source.length() && source.charAt(i + 1) == '/')
            {
                while (i < source.length() && source.charAt(i) != '\n')
                {
                    out.append(' ');
                    i++;
                }
            }
            else
            {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    /**
     * Java 8 source level: {@code Files.readString} arrived in 11, and this
     * class stays on the release-8 source set deliberately so it runs on every
     * leg rather than only the Java 25 ones.
     */
    private static String read(Path path) throws IOException
    {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    private static Path resolveFipsTree()
    {
        for (Path base : new Path[]{Paths.get(""), Paths.get(".."), Paths.get("jostle")})
        {
            Path p = base.resolve(FIPS_TREE);
            if (Files.isDirectory(p))
            {
                return p;
            }
        }
        return null;
    }
}
