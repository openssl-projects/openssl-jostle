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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The hybrid KEM bridges copy private material only where the copy is cleansed. JNI: the private half going out
 * goes through load_secret_output_ctx and the decode input through load_secret_input_ctx, in both trees; the public
 * share going out is a plain load. FFM: the arena copy of the private half is zero-filled before the arena closes.
 * Order pins ride here too: the shared JNI decode tests the input before the load, both decoders reach it, and the
 * FFM generate asserts its out pointer.
 */
public class MLXKEMSecretArraySourcePinTest
{
    private static final String PLAIN = "load_bytearray_ctx";
    private static final String SECRET_IN = "load_secret_input_ctx";
    private static final String SECRET_OUT = "load_secret_output_ctx";
    private static final String BRIDGE = "mlxkem_decode_bridge";
    // A JNI entry point or a static helper: the decoders share one body.
    private static final Pattern FUNCTION = Pattern.compile(
            "(?:MLXKEMServiceJNI_ni_1(\\w+?)(?:__\\w+)?|static jint (\\w+))\\s*\\(");
    private static final Pattern LOAD = Pattern.compile("(" + PLAIN + "|" + SECRET_IN + "|" + SECRET_OUT + ")"
            + "\\(\\s*&\\w+\\s*,\\s*env\\s*,\\s*(\\w+)\\s*\\)");

    /** Every array load in the JNI glue, keyed by function, with the helper it goes through. */
    private static Map<String, String> expected()
    {
        Map<String, String> m = new TreeMap<String, String>();
        m.put("getPublicKey", PLAIN + " _output");
        m.put("getPrivateKey", SECRET_OUT + " _output");
        m.put(BRIDGE, SECRET_IN + " _input");
        return m;
    }

    private static String jni(Path root, String tree) throws IOException
    {
        return stripComments(read(root.resolve("interface/" + tree + "/jni/mlxkem_ni_jni.c")));
    }

    @Test
    public void privateMaterialCrossesOnlyThroughTheSecretHelpers() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            Assertions.assertEquals(expected(), loadsByFunction(jni(root, tree)), tree);
        }
    }

    /** The FFM marshalling zero-fills the private-half copy, in a finally. */
    @Test
    public void ffmZeroFillsThePrivateCopy() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String src = stripComments(read(root.resolve(
                "jostle/src/main/java25/org/openssl/jostle/jcajce/provider/mlxkem/MLXKEMServiceFFM.java")));
        String signature = "public int ni_decode_privateKey(";
        int start = src.indexOf(signature);
        Assertions.assertTrue(start >= 0, signature + " not found");
        String body = src.substring(start, src.indexOf("\n    }\n", start));
        String call = "zero(refInput)";
        Assertions.assertTrue(body.contains(call), "the private copy is not zero-filled");
        Assertions.assertTrue(body.indexOf("finally") >= 0 && body.indexOf("finally") < body.indexOf(call),
                "zero-fill outside finally");
    }

    /** The shared decode tests the input before it loads it, and both decoders go through it, in both trees. */
    @Test
    public void theDecodersTestTheInputBeforeTheLoad() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            Map<String, String> bodies = bodiesByFunction(jni(root, tree));
            String body = bodies.get(BRIDGE);
            Assertions.assertNotNull(body, tree + " " + BRIDGE + " not found");
            int test = body.indexOf("if (_input == NULL)");
            int load = body.indexOf(", env, _input)");
            Assertions.assertTrue(test >= 0, tree + " never tests the input");
            Assertions.assertTrue(load >= 0, tree + " never loads the input");
            Assertions.assertTrue(test < load, tree + " loads the input before testing it");
            for (String entry : new String[]{"decode_1publicKey", "decode_1privateKey"})
            {
                Assertions.assertTrue(bodies.get(entry).contains("return " + BRIDGE + "("), tree + " " + entry);
            }
        }
    }

    /** The FFM generate asserts its out pointer before writing through it, in both trees. */
    @Test
    public void theFfmGenerateAssertsItsOutPointer() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            String path = "interface/" + tree + "/ffm/mlxkem_ni_ffm.c";
            String src = stripComments(read(root.resolve(path)));
            String regex = "JoMLXKEM_generateKeyPair\\(int32_t type, int32_t \\*ret_val, void \\*rnd_src\\) \\{\\s*"
                    + "jo_assert\\(ret_val != NULL\\);";
            Assertions.assertTrue(Pattern.compile(regex).matcher(src).find(), path + " does not match " + regex);
        }
    }

    /** The source-level guard also reads CRLF input identically. */
    @Test
    public void theScanIsLineEndingIndependent() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String lf = read(root.resolve("interface/nonfips/jni/mlxkem_ni_jni.c"));
        String crlf = lf.replace("\n", "\r\n");
        Assertions.assertEquals(loadsByFunction(stripComments(lf)), loadsByFunction(stripComments(normalise(crlf))));
    }

    private static Map<String, String> bodiesByFunction(String src)
    {
        Map<String, String> out = new TreeMap<String, String>();
        Matcher f = FUNCTION.matcher(src);
        int[] starts = new int[64];
        String[] names = new String[64];
        int n = 0;
        while (f.find())
        {
            starts[n] = f.start();
            names[n++] = f.group(1) != null ? f.group(1) : f.group(2);
        }
        // Five entry points and the shared decode.
        Assertions.assertTrue(n >= 6, "read only " + n + " functions");
        for (int i = 0; i < n; i++)
        {
            out.put(names[i], src.substring(starts[i], i + 1 < n ? starts[i + 1] : src.length()));
        }
        return out;
    }

    private static Map<String, String> loadsByFunction(String src)
    {
        Map<String, String> out = new TreeMap<String, String>();
        for (Map.Entry<String, String> e : bodiesByFunction(src).entrySet())
        {
            Matcher l = LOAD.matcher(e.getValue());
            while (l.find())
            {
                String prior = out.put(e.getKey(), l.group(1) + " " + l.group(2));
                Assertions.assertNull(prior, e.getKey() + " loads two arrays");
            }
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
