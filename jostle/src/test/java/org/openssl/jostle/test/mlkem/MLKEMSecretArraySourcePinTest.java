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

package org.openssl.jostle.test.mlkem;

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
 * The ML-KEM bridges copy private material only where the copy is cleansed. JNI: the seed and the private key coming
 * in go through load_secret_input_ctx, the private key and the seed going out through load_secret_output_ctx, in
 * both trees; every other array is a plain load. FFM: the arena copies of the seed and of the private key are
 * zero-filled before the arena closes. Order pins ride here too: the JNI decoders test the input before the load,
 * and the FFM generates assert their out pointer.
 */
public class MLKEMSecretArraySourcePinTest
{
    private static final String PLAIN = "load_bytearray_ctx";
    private static final String SECRET_IN = "load_secret_input_ctx";
    private static final String SECRET_OUT = "load_secret_output_ctx";
    private static final Pattern ENTRY = Pattern.compile("MLKEMServiceJNI_ni_1(\\w+?)(?:__\\w+)?\\s*\\(");
    private static final Pattern LOAD = Pattern.compile("(" + PLAIN + "|" + SECRET_IN + "|" + SECRET_OUT + ")"
            + "\\(\\s*&\\w+\\s*,\\s*env\\s*,\\s*(\\w+)\\s*\\)");

    /** Every array load in the JNI glue, keyed by entry point, with the helper it goes through. */
    private static Map<String, String> expected()
    {
        Map<String, String> m = new TreeMap<String, String>();
        m.put("generateKeyPair", SECRET_IN + " _seed");
        m.put("decode_1publicKey", PLAIN + " _input");
        m.put("decode_1privateKey", SECRET_IN + " _input");
        m.put("getPrivateKey", SECRET_OUT + " _output");
        m.put("getSeed", SECRET_OUT + " _output");
        m.put("getPublicKey", PLAIN + " _output");
        return m;
    }

    @Test
    public void privateMaterialCrossesOnlyThroughTheSecretHelpers() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            String src = stripComments(read(root.resolve("interface/" + tree + "/jni/mlkem_ni_jni.c")));
            Assertions.assertEquals(expected(), loadsByEntry(src), tree);
        }
    }

    /** The FFM marshalling zero-fills the seed copy and the private-key copy, each in a finally. */
    @Test
    public void ffmZeroFillsTheSeedAndPrivateKeyCopies() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String src = stripComments(read(root.resolve(
                "jostle/src/main/java25/org/openssl/jostle/jcajce/provider/mlkem/MLKEMServiceFFM.java")));
        assertZeroFilledInFinally(src, "public long ni_generateKeyPair(int type, int[] err, byte[] seed", "seedRef");
        assertZeroFilledInFinally(src, "public int ni_decode_privateKey(", "inputRef");
    }

    private static void assertZeroFilledInFinally(String src, String signature, String segment)
    {
        int start = src.indexOf(signature);
        Assertions.assertTrue(start >= 0, signature + " not found");
        String body = src.substring(start, src.indexOf("\n    }\n", start));
        String call = "zero(" + segment + ")";
        Assertions.assertTrue(body.contains(call), signature + ": the copy is not zero-filled");
        Assertions.assertTrue(body.indexOf("finally") >= 0 && body.indexOf("finally") < body.indexOf(call),
                signature + ": zero-fill outside finally");
    }

    /** Both JNI decoders test the input before they load it, in both trees. */
    @Test
    public void theDecodersTestTheInputBeforeTheLoad() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            String src = stripComments(read(root.resolve("interface/" + tree + "/jni/mlkem_ni_jni.c")));
            for (String entry : new String[]{"decode_1publicKey", "decode_1privateKey"})
            {
                int start = src.indexOf("MLKEMServiceJNI_ni_1" + entry);
                Assertions.assertTrue(start >= 0, tree + " " + entry + " not found");
                int end = src.indexOf("JNIEXPORT", start);
                String body = src.substring(start, end < 0 ? src.length() : end);
                int test = body.indexOf("if (_input == NULL)");
                int load = body.indexOf(", env, _input)");
                Assertions.assertTrue(test >= 0, tree + " " + entry + " never tests the input");
                Assertions.assertTrue(load >= 0, tree + " " + entry + " never loads the input");
                Assertions.assertTrue(test < load, tree + " " + entry + " loads the input before testing it");
            }
        }
    }

    /** Both FFM generates assert their out pointer before writing through it, in both trees. */
    @Test
    public void theFfmGeneratesAssertTheirOutPointer() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            requireMatch(root, "interface/" + tree + "/ffm/mlkem_ni_ffm.c",
                    "JoMLKEM_generateKeyPair\\(int32_t type, int32_t \\*ret_val, void \\*rnd_src\\) \\{\\s*"
                            + "jo_assert\\(ret_val != NULL\\);");
            requireMatch(root, "interface/" + tree + "/ffm/mlkem_ni_ffm.c",
                    "int32_t seed_len, void \\*rand_src\\) \\{\\s*jo_assert\\(ret_val != NULL\\);");
        }
    }

    private static void requireMatch(Path root, String path, String regex) throws IOException
    {
        String src = stripComments(read(root.resolve(path)));
        Assertions.assertTrue(Pattern.compile(regex).matcher(src).find(), path + " does not match " + regex);
    }

    /** The source-level guard also reads CRLF input identically. */
    @Test
    public void theScanIsLineEndingIndependent() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String lf = read(root.resolve("interface/nonfips/jni/mlkem_ni_jni.c"));
        String crlf = lf.replace("\n", "\r\n");
        Assertions.assertEquals(loadsByEntry(stripComments(lf)), loadsByEntry(stripComments(normalise(crlf))));
    }

    private static Map<String, String> loadsByEntry(String src)
    {
        Map<String, String> out = new TreeMap<String, String>();
        Matcher e = ENTRY.matcher(src);
        int[] starts = new int[64];
        String[] names = new String[64];
        int n = 0;
        while (e.find())
        {
            starts[n] = e.start();
            names[n++] = e.group(1);
        }
        Assertions.assertTrue(n >= 7, "read only " + n + " entry points");
        for (int i = 0; i < n; i++)
        {
            String body = src.substring(starts[i], i + 1 < n ? starts[i + 1] : src.length());
            Matcher l = LOAD.matcher(body);
            while (l.find())
            {
                String prior = out.put(names[i], l.group(1) + " " + l.group(2));
                Assertions.assertNull(prior, names[i] + " loads two arrays");
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
