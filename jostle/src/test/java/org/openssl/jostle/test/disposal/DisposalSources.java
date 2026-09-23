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

package org.openssl.jostle.test.disposal;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Reads the {@code NativeReference} family list from the SOURCE tree.
 *
 * <p>Reflection would answer about the copy the JVM loaded and say nothing about
 * the others, so the baseline source set is scanned instead -- the technique
 * {@code NativeReferenceParityTest} uses.
 */
public final class DisposalSources
{
    private DisposalSources()
    {
    }

    private static final String BASELINE = "jostle/src/main/java";

    /** Simple names of every class extending {@code NativeReference} in the baseline. */
    public static Set<String> nativeReferenceFamilies()
    {
        Path root = resolve(BASELINE);
        if (root == null)
        {
            throw new IllegalStateException(BASELINE + " is not reachable from "
                    + Paths.get("").toAbsolutePath());
        }

        Set<String> out = new LinkedHashSet<String>();
        try (Stream<Path> walk = Files.walk(root))
        {
            List<Path> sources = walk.filter(p -> p.getFileName().toString().endsWith(".java"))
                    .collect(Collectors.toList());
            for (Path p : sources)
            {
                String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                if (stripComments(text).contains("extends NativeReference"))
                {
                    String name = p.getFileName().toString();
                    out.add(name.substring(0, name.length() - ".java".length()));
                }
            }
        }
        catch (IOException e)
        {
            throw new UncheckedIOException(e);
        }
        return out;
    }

    /** Javadoc naming the base class reads exactly like a class that extends it. */
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

    private static Path resolve(String relative)
    {
        for (Path base : new Path[]{Paths.get(""), Paths.get(".."), Paths.get("jostle")})
        {
            Path p = base.resolve(relative);
            if (Files.isDirectory(p))
            {
                return p;
            }
        }
        // the leg may run from the module directory
        Path alt = Paths.get("src/main/java");
        return Files.isDirectory(alt) ? alt : null;
    }
}
