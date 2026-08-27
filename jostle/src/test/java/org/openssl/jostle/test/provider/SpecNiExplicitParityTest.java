/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level parity guard: inside {@code jcajce/provider/**}, every
 * {@code new PKEYKeySpec(...)} must pass an explicit {@code SpecNI}.
 *
 * <h2>The trap this exists for (MT-15)</h2>
 *
 * {@code PKEYKeySpec} offers convenience overloads that default to
 * {@code NISelector.SpecNI} — the BASE library. They are correct only in
 * base-only code. {@code EdKeyFactorySpi} used one from a class that JSLFIPS
 * also registers:
 *
 * <pre>
 *   new PKEYKeySpec(specNI.allocate(), osslKeyType)
 * </pre>
 *
 * allocating through the FIPS library and recording the base one. Disposal
 * routes through the recorded NI, so those keys were freed across libraries —
 * and {@code PKEYKeySpec.Disposer} states the very invariant being broken,
 * two files away: <i>"The NI that allocated the PKEY frees it - a
 * FIPS-allocated key must be disposed through the FIPS interface library."</i>
 *
 * <p>An invariant documented at one end and violated at the other is what a
 * source guard is for. No runtime test found this in the time it existed: the
 * keys work, the values are right, and the cross-library free is a latent
 * crash rather than a wrong answer.
 *
 * <h2>Why a lint and not deleting the overloads</h2>
 *
 * Enumerated before choosing: exactly TWO production call sites used the
 * defaulting overloads, both the Ed defect. Deleting them would therefore be
 * nearly free internally — but {@code PKEYKeySpec} lives in
 * {@code org.openssl.jostle.jcajce.spec}, which {@code module-info.java}
 * EXPORTS, so they are public API and removal breaks external callers. The
 * lint gets the same protection where it matters (our own provider code) while
 * leaving the published surface alone.
 */
public class SpecNiExplicitParityTest
{
    /** {@code new PKEYKeySpec(} followed by its first argument. */
    private static final Pattern CALL =
            Pattern.compile("new\\s+PKEYKeySpec\\s*\\(\\s*([^,)]+)", Pattern.DOTALL);

    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    private static final Pattern STRING_LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"");

    @Test
    public void everyKeySpecConstructionNamesItsSpecNi()
    {
        List<Path> roots = providerRoots();
        Assumptions.assumeFalse(roots.isEmpty(),
                "no provider source root reachable from " + Paths.get("").toAbsolutePath()
                        + " — source-level lint, skipped rather than failed");

        List<String> violations = new ArrayList<String>();
        int checked = 0;

        for (Path root : roots)
        {
            for (Path source : javaSourcesUnder(root))
            {
                String code = strip(read(source));
                Matcher m = CALL.matcher(code);
                while (m.find())
                {
                    checked++;
                    String first = m.group(1).trim();
                    // An explicit SpecNI is the only acceptable first argument.
                    // "specNI.allocate()" is NOT one — that is the MT-15 bug
                    // exactly: it allocates through the right library and then
                    // lets the overload record the wrong one.
                    // The first-argument capture stops at any '(' , so
                    // "spec.getSpecNI()" arrives as "spec.getSpecNI(" —
                    // normalise before matching. The first version of this
                    // guard flagged four correct call sites for exactly that.
                    String head = first.endsWith("(") ? first.substring(0, first.length() - 1) : first;
                    boolean explicit = head.equals("specNI")
                            || head.endsWith("SpecNI")
                            || head.endsWith("getSpecNI");
                    if (!explicit)
                    {
                        int line = code.substring(0, m.start()).split("\n", -1).length;
                        violations.add(source.getFileName() + ":" + line
                                + "  new PKEYKeySpec(" + first + " ...)");
                    }
                }
            }
        }

        Assertions.assertTrue(checked > 20,
                "only " + checked + " PKEYKeySpec constructions scanned — the guard is not "
                        + "looking where it thinks and would pass vacuously");

        Assertions.assertTrue(violations.isEmpty(),
                "these construct a PKEYKeySpec without naming a SpecNI, so it defaults to "
                        + "NISelector.SpecNI — the BASE library. In any class the FIPS provider "
                        + "also registers, that records the wrong library and disposal frees "
                        + "across libraries (MT-15). Pass the SPI's own specNI explicitly:\n  "
                        + String.join("\n  ", violations));
    }

    private static String strip(String body)
    {
        String s = LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
        return STRING_LITERAL.matcher(s).replaceAll("\"\"");
    }

    private static List<Path> providerRoots()
    {
        String pkg = "org/openssl/jostle/jcajce/provider";
        String[] bases = {"src/main", "jostle/src/main"};
        String[] levels = {"java", "java9", "java11", "java15", "java17", "java21", "java25"};
        List<Path> found = new ArrayList<Path>();
        for (String base : bases)
        {
            for (String level : levels)
            {
                Path p = Paths.get(base, level).resolve(pkg);
                if (Files.isDirectory(p))
                {
                    found.add(p.toAbsolutePath().normalize());
                }
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
