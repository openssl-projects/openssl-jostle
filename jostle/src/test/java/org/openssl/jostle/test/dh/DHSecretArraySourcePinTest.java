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

package org.openssl.jostle.test.dh;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The DH bridges copy secrets only where the copy is cleansed. JNI: x comes in through load_secret_input_ctx, and
 * the component getter's and the derive's outputs go out through load_secret_output_ctx, in both trees. FFM: the
 * arena copies of x and of the derived secret are zero-filled before the arena closes.
 */
public class DHSecretArraySourcePinTest
{
    private static final List<String> PRIVATE_INPUTS = Collections.singletonList("_x");
    private static final List<String> SECRET_OUTPUTS = Arrays.asList("_out", "_out");

    @Test
    public void privateComponentsCrossOnlyThroughTheSecretHelpers() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            String src = stripComments(read(root.resolve("interface/" + tree + "/jni/dh_ni_jni.c")));

            List<String> plain = arguments(src, "load_bytearray_ctx");
            Assertions.assertTrue(plain.size() >= 5, tree + ": plain loads not found, the scan reads nothing");
            Assertions.assertFalse(plain.contains("_out"), tree + ": an output loaded through load_bytearray_ctx");
            for (String arg : plain)
            {
                Assertions.assertFalse(PRIVATE_INPUTS.contains(arg) || SECRET_OUTPUTS.contains(arg),
                        tree + ": private argument " + arg + " loaded through load_bytearray_ctx");
            }

            List<String> inputs = arguments(src, "load_secret_input_ctx");
            Collections.sort(inputs);
            Assertions.assertEquals(PRIVATE_INPUTS, inputs, tree);
            Assertions.assertEquals(SECRET_OUTPUTS, arguments(src, "load_secret_output_ctx"), tree);
        }
    }

    /** The FFM marshalling zero-fills the arena copies of x and of the derived secret. */
    @Test
    public void ffmZeroFillsTheArenaCopies() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String src = stripComments(read(root.resolve(
                "jostle/src/main/java25/org/openssl/jostle/jcajce/provider/dh/DHServiceFFM.java")));
        Assertions.assertTrue(body(src, "ni_makePrivateFromComponents").contains("zero(xSeg)"), "x");
        Assertions.assertTrue(body(src, "ni_kexDerive").contains("zero(outSeg)"), "derive output");
    }

    private static String body(String src, String method)
    {
        int start = src.indexOf("public " + (method.equals("ni_kexDerive") ? "int " : "long ") + method + "(");
        Assertions.assertTrue(start >= 0, method + " not found");
        int end = src.indexOf("\n    }\n", start);
        return src.substring(start, end);
    }

    /** The source-level guard also reads CRLF input identically. */
    @Test
    public void theScanIsLineEndingIndependent() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String lf = read(root.resolve("interface/nonfips/jni/dh_ni_jni.c"));
        String crlf = lf.replace("\n", "\r\n");
        for (String helper : new String[]{"load_bytearray_ctx", "load_secret_input_ctx", "load_secret_output_ctx"})
        {
            Assertions.assertEquals(arguments(stripComments(lf), helper),
                    arguments(stripComments(normalise(crlf)), helper), helper);
        }
    }

    private static List<String> arguments(String src, String helper)
    {
        Matcher m = Pattern.compile(helper + "\\(\\s*&\\w+\\s*,\\s*env\\s*,\\s*(\\w+)\\s*\\)").matcher(src);
        List<String> out = new ArrayList<String>();
        while (m.find())
        {
            out.add(m.group(1));
        }
        return out;
    }

    private static String stripComments(String src)
    {
        return src.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("//[^\n]*", " ");
    }

    private static String read(Path p) throws IOException
    {
        return normalise(new String(Files.readAllBytes(p), StandardCharsets.UTF_8));
    }

    private static String normalise(String s)
    {
        return s.replace("\r\n", "\n");
    }

    private static Path repoRoot()
    {
        Path p = Paths.get("").toAbsolutePath();
        for (int i = 0; i < 6 && p != null; i++)
        {
            if (Files.isDirectory(p.resolve("interface")) && Files.isDirectory(p.resolve("jostle/src/test")))
            {
                return p;
            }
            p = p.getParent();
        }
        return null;
    }
}
