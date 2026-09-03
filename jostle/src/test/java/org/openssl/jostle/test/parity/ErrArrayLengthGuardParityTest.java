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

package org.openssl.jostle.test.parity;

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
 * Source lint: every {@code GetIntArrayElements} on an error out-array is
 * preceded, in the same function, by a {@code GetArrayLength} check.
 *
 * <h2>Why this is a guard and not merely tidiness</h2>
 *
 * <p>The err out-array is jostle's OWN PLUMBING — the SPI constructs it and no
 * external caller supplies it — so its shape is an invariant we guarantee, and
 * a violated invariant may abort (Megan, 2026-09-02: <i>"error is not expected
 * to be null so an abort is acceptable"</i>, <i>"it's like that because we
 * control it"</i>). What an invariant may NOT do is get violated by CORRUPTING
 * MEMORY. {@code GetIntArrayElements} on a zero-length array returns a valid
 * pointer to a zero-length buffer, and the following {@code *err = code} stores
 * four bytes past the end — measured as a JVM SIGBUS, frame
 * {@code libinterface_jni.dylib allocate_mac+0xe4}, reachable from pure Java
 * through the NI surface. So the invariant is asserted BEFORE the pointer is
 * taken, which aborts deterministically instead.
 *
 * <p>{@code SetIntArrayRegion} sites need no guard — the JVM bounds-checks them
 * and raises ArrayIndexOutOfBoundsException. Only the GetIntArrayElements idiom
 * corrupts, which is why this lint keys on it rather than on "err array".
 *
 * <p>An abort cannot be pinned by a test in-process (it takes the fork down), so
 * this source lint is what holds the fix. It covers all sites statically,
 * including the five in {@code ks_jni.c} that need a live keystore handle to
 * reach and were therefore accepted as static rather than measured.
 */
public class ErrArrayLengthGuardParityTest
{
    private static final Pattern GET_ELEMENTS = Pattern.compile(
            "GetIntArrayElements\\s*\\(\\s*env\\s*,\\s*([A-Za-z_]\\w*)\\s*,");

    @Test
    public void everyErrArrayElementsAccessIsLengthChecked()
    {
        final List<Path> dirs = new ArrayList<Path>();
        for (String d : new String[]{"interface/nonfips/jni", "interface/fips/jni"})
        {
            Path p = resolve(d, "../" + d);
            if (p != null)
            {
                dirs.add(p);
            }
        }
        Assumptions.assumeTrue(!dirs.isEmpty(),
                "source tree not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") — this guard is source-level "
                        + "and only runs from a checkout");

        final List<String> unguarded = new ArrayList<String>();
        int examined = 0;

        for (Path dir : dirs)
        {
            for (Path c : listFiles(dir, ".c"))
            {
                // Comments in spec_ni_jni.c and asn1_ni_jni.c discuss zero-length
                // arrays and GetArrayLength in prose. A comment must not be able
                // to satisfy the guard, so strip before matching — every source
                // lint in this repo needed this.
                final String src = stripCommentsAndStrings(read(c));
                for (String fn : src.split("(?=JNIEXPORT)"))
                {
                    final Matcher m = GET_ELEMENTS.matcher(fn);
                    while (m.find())
                    {
                        examined++;
                        final String arr = m.group(1);
                        final String before = fn.substring(0, m.start());
                        if (!before.contains("GetArrayLength(env, " + arr + ")")
                                && !before.contains("GetArrayLength(env," + arr + ")"))
                        {
                            unguarded.add(c.getFileName() + "  " + arr);
                        }
                    }
                }
            }
        }

        Assertions.assertTrue(examined > 0,
                "no GetIntArrayElements sites were examined — the guard is vacuous");
        Assertions.assertTrue(unguarded.isEmpty(),
                "an err array reaches GetIntArrayElements with no preceding GetArrayLength "
                        + "check, so a zero-length array stores past the end of the buffer "
                        + "(measured: JVM SIGBUS):\n  " + String.join("\n  ", unguarded));
    }

    private static String stripCommentsAndStrings(String src)
    {
        String s = src.replaceAll("(?s)/\\*.*?\\*/", " ");
        s = s.replaceAll("(?m)//.*$", " ");
        s = s.replaceAll("\"(\\\\.|[^\"\\\\])*\"", "\"\"");
        return s;
    }

    private static Path resolve(String... candidates)
    {
        for (String c : candidates)
        {
            Path p = Paths.get(c);
            if (Files.isDirectory(p))
            {
                return p.toAbsolutePath().normalize();
            }
        }
        return null;
    }

    private static List<Path> listFiles(Path dir, String suffix)
    {
        final List<Path> out = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> walk = Files.walk(dir, 1))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(suffix)).forEach(out::add);
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
        java.util.Collections.sort(out);
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
