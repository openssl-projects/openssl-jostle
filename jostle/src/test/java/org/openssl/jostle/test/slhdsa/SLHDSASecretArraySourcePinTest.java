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

package org.openssl.jostle.test.slhdsa;

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
 * The SLH-DSA bridges copy private material only where the copy is cleansed. JNI: the seed and the private key
 * coming in go through load_secret_input_ctx, the private key going out through load_secret_output_ctx, in both
 * trees; every other array is a plain load. FFM: the arena copy of the seed is zero-filled before the arena closes.
 * Two alignment pins ride here too: ni_sign is an int on every layer, and the JNI decoders test the input first.
 */
public class SLHDSASecretArraySourcePinTest
{
    private static final String PLAIN = "load_bytearray_ctx";
    private static final String SECRET_IN = "load_secret_input_ctx";
    private static final String SECRET_OUT = "load_secret_output_ctx";
    private static final Pattern ENTRY = Pattern.compile("SLHDSAServiceJNI_ni_1(\\w+?)(?:__\\w+)?\\s*\\(");
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
        m.put("getPublicKey", PLAIN + " _output");
        m.put("initVerify", PLAIN + " _context");
        m.put("initSign", PLAIN + " _context");
        m.put("sign", PLAIN + " _output");
        m.put("verify", PLAIN + " _sig");
        return m;
    }

    @Test
    public void privateMaterialCrossesOnlyThroughTheSecretHelpers() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            String src = stripComments(read(root.resolve("interface/" + tree + "/jni/slhdsa_ni_jni.c")));
            Assertions.assertEquals(expected(), loadsByEntry(src), tree);
        }
    }

    /** The FFM marshalling zero-fills the arena copy of the seed. */
    @Test
    public void ffmZeroFillsTheSeedCopy() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String src = stripComments(read(root.resolve(
                "jostle/src/main/java25/org/openssl/jostle/jcajce/provider/slhdsa/SLHDSAServiceFFM.java")));
        int start = src.indexOf("public long ni_generateKeyPair(int type, int[] err, byte[] seed");
        Assertions.assertTrue(start >= 0, "the seeded ni_generateKeyPair not found");
        int end = src.indexOf("\n    }\n", start);
        String body = src.substring(start, end);
        Assertions.assertTrue(body.contains("zero(seedRef)"), "the seed copy is not zero-filled");
        Assertions.assertTrue(body.indexOf("finally") < body.indexOf("zero(seedRef)"), "zero-fill outside finally");
    }

    /** ni_sign answers an int on every layer: the Java interface, both JNI glues, both JNI classes and FFM. */
    @Test
    public void niSignIsAnIntOnEveryLayer() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        String java = "jostle/src/main/java/org/openssl/jostle/jcajce/provider/";
        requireMatch(root, java + "slhdsa/SLHDSAServiceNI.java", "\\n\\s*int ni_sign\\(long ref,");
        requireMatch(root, java + "slhdsa/SLHDSAServiceJNI.java", "public native int ni_sign\\(");
        requireMatch(root, java + "fips/SLHDSAServiceFIPSJNI.java", "public native int ni_sign\\(");
        requireMatch(root, "jostle/src/main/java25/org/openssl/jostle/jcajce/provider/slhdsa/SLHDSAServiceFFM.java",
                "public int ni_sign\\(");
        requireMatch(root, "jostle/src/main/java25/org/openssl/jostle/jcajce/provider/slhdsa/SLHDSAServiceFFM.java",
                "JoSLHDSA_sign\"\\)\\.orElseThrow\\(\\);\\s*signerFuncHandle = linker\\.downcallHandle\\(signerFunc,"
                        + "\\s*FunctionDescriptor\\.of\\(\\s*ValueLayout\\.JAVA_INT,");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            requireMatch(root, "interface/" + tree + "/jni/slhdsa_ni_jni.c",
                    "JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_slhdsa_"
                            + "SLHDSAServiceJNI_ni_1sign\\b");
            requireMatch(root, "interface/" + tree + "/ffm/slhdsa_ni_ffm.c", "\\nint32_t JoSLHDSA_sign\\(");
        }
    }

    /** Both JNI decoders refuse a null input before they load it, in both trees. */
    @Test
    public void theDecodersTestTheInputBeforeTheLoad() throws IOException
    {
        Path root = repoRoot();
        Assertions.assertNotNull(root, "repository root not found");
        for (String tree : new String[]{"nonfips", "fips"})
        {
            String src = stripComments(read(root.resolve("interface/" + tree + "/jni/slhdsa_ni_jni.c")));
            for (String entry : new String[]{"decode_1publicKey", "decode_1privateKey"})
            {
                int start = src.indexOf("SLHDSAServiceJNI_ni_1" + entry);
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
        String lf = read(root.resolve("interface/nonfips/jni/slhdsa_ni_jni.c"));
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
        Assertions.assertTrue(n >= 13, "read only " + n + " entry points");
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
