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

package org.openssl.jostle.test.provider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Shared comment/string-literal stripping and file-walking helpers for the
 * production-source lint tests in this package (avoids re-deriving the same
 * primitives {@code NoJdkProviderNamesInProductionTest} and
 * {@code UnpinnedServiceResolutionParityTest} already carry, for a third
 * lint of the same shape).
 */
final class ProductionSourceLint
{
    private ProductionSourceLint()
    {
    }

    static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    static final Pattern STRING_LITERAL = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"");

    /** Strips block and line comments only — string literals are preserved. */
    static String stripComments(String body)
    {
        return LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(body).replaceAll(" ")).replaceAll(" ");
    }

    /** Strips comments AND the contents of string literals — for matching CODE tokens. */
    static String stripCode(String body)
    {
        return STRING_LITERAL.matcher(stripComments(body)).replaceAll("\"\"");
    }

    static List<Path> javaSourcesUnder(Path root) throws IOException
    {
        final List<Path> out = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> walk = Files.walk(root))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(".java")).forEach(out::add);
        }
        return out;
    }
}
