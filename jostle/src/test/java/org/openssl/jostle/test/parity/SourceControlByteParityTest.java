/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.parity;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * No Java or C source holds a control byte other than tab, LF and CR.
 *
 * <p>A raw control byte is invisible in an editor and makes {@code file} and {@code grep} treat the file as
 * binary, so a grep over the tree silently skips every line of it. Write {@code "\0"} as an escape.
 *
 * <p>Its inputs include {@code interface/}, which is not a Gradle test task input; falsify with {@code --rerun}.
 */
public class SourceControlByteParityTest
{
    private static final String[] ROOTS = {"jostle/src", "interface/nonfips", "interface/fips"};

    private static Path repoRoot()
    {
        Path p = Paths.get("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("interface")))
        {
            p = p.getParent();
        }
        Assertions.assertNotNull(p, "could not locate the repository root from " + Paths.get("").toAbsolutePath());
        return p;
    }

    private static boolean isSource(Path p)
    {
        String n = p.getFileName().toString();
        return n.endsWith(".java") || n.endsWith(".c") || n.endsWith(".h");
    }

    @Test
    public void noSourceHoldsAControlByte() throws IOException
    {
        Path root = repoRoot();
        List<Path> files = new ArrayList<>();
        for (String r : ROOTS)
        {
            try (Stream<Path> walk = Files.walk(root.resolve(r)))
            {
                files.addAll(walk.filter(Files::isRegularFile).filter(SourceControlByteParityTest::isSource)
                        .filter(p -> !p.toString().contains("CMakeFiles")).collect(Collectors.toList()));
            }
        }
        // A walk that finds almost nothing is a broken walk, not a clean tree.
        Assertions.assertTrue(files.size() > 1000, "scanned only " + files.size() + " source files");

        List<String> offenders = new ArrayList<>();
        for (Path f : files)
        {
            byte[] b = Files.readAllBytes(f);
            int line = 1;
            for (byte x : b)
            {
                if (x == '\n')
                {
                    line++;
                }
                else if (x >= 0 && x < 0x20 && x != '\t' && x != '\r')
                {
                    offenders.add(root.relativize(f) + ":" + line + " byte 0x" + Integer.toHexString(x));
                    break;
                }
            }
        }
        Assertions.assertTrue(offenders.isEmpty(), "control bytes in source:\n  " + String.join("\n  ", offenders));
    }
}
