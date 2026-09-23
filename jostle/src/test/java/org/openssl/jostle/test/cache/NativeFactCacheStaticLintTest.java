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

package org.openssl.jostle.test.cache;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * No {@code NativeLengthCache} is held in a static, in any source set. A static
 * cache is shared by every NI instance, so a fact one module reported would
 * answer for the other.
 *
 * <p>An interface field counts too: it is static without the keyword.
 *
 * <p>Every source set is read as text, because a multi-release copy is invisible
 * to reflection on the loaded class. Comments are stripped first, so prose
 * naming the class does not count, and lines are split on {@code \r?\n} so a
 * CRLF checkout scans the same as an LF one; the test proves both.
 */
public class NativeFactCacheStaticLintTest
{
    private static final String MAIN = "jostle/src/main";

    /** Far fewer than the tree holds; an empty or misrooted walk cannot reach it. */
    private static final int MIN_SOURCES = 300;

    /** A static declaration whose type is the cache, possibly spread over lines. */
    private static final Pattern STATIC_CACHE =
            Pattern.compile("\\bstatic\\b[^;={}()]*?\\bNativeLengthCache\\b");

    /** A field of an interface is static without saying so. */
    private static final Pattern INTERFACE_FIELD =
            Pattern.compile("\\bNativeLengthCache\\s*<[^>;(]*>\\s+\\w+\\s*=");

    private static final Pattern IS_INTERFACE = Pattern.compile("(?m)^\\s*(public\\s+)?interface\\s+\\w+");

    private static final Pattern ACCESSOR =
            Pattern.compile("\\bNativeLengthCache\\s*<[^>]*>\\s+lengthCache\\s*\\(\\s*\\)\\s*\\{");

    @Test
    public void theMatcherFiresOnAStaticAndStaysSilentOnProse()
    {
        String bad = "class X {\n    private static final NativeLengthCache<String> c = null;\n}\n";
        String split = "class X {\n    private static\n        final NativeLengthCache<String> c = null;\n}\n";
        String prose = "class X {\n    /** Not a static NativeLengthCache, just prose. */\n"
                + "    // static NativeLengthCache in a comment\n"
                + "    private final NativeLengthCache<String> c = null;\n}\n";
        String ifaceField = "interface X {\n    NativeLengthCache<String> SHARED = null;\n}\n";
        String ifaceAccessor = "interface X {\n    NativeLengthCache<String> lengthCache();\n}\n";

        for (String text : new String[]{bad, split})
        {
            Assertions.assertEquals(1, staticSites(text).size(), "missed a static in:\n" + text);
            Assertions.assertEquals(staticSites(text), staticSites(crlf(text)), "CRLF changed the finding");
        }
        Assertions.assertEquals(2, staticSites(bad).get(0).intValue(), "wrong line for the static");
        Assertions.assertEquals(3, staticSites(split).get(0).intValue(), "wrong line for the split static");
        Assertions.assertTrue(staticSites(prose).isEmpty(), "comments or an instance field counted as a static");
        Assertions.assertTrue(staticSites(crlf(prose)).isEmpty(), "CRLF prose counted as a static");
        Assertions.assertEquals(1, staticSites(ifaceField).size(), "missed an interface field, static by default");
        Assertions.assertEquals(2, staticSites(crlf(ifaceField)).get(0).intValue(), "wrong line, CRLF interface field");
        Assertions.assertTrue(staticSites(ifaceAccessor).isEmpty(), "the interface accessor counted as a field");
    }

    @Test
    public void noSourceSetHoldsTheCacheInAStatic() throws IOException
    {
        Map<Path, String> texts = readTree();
        List<String> asCheckedOut = scan(texts);

        Map<Path, String> withCarriageReturns = new LinkedHashMap<Path, String>();
        for (Map.Entry<Path, String> e : texts.entrySet())
        {
            withCarriageReturns.put(e.getKey(), crlf(e.getValue()));
        }
        Assertions.assertEquals(asCheckedOut, scan(withCarriageReturns),
                "this scan is not line-ending independent");

        Assertions.assertTrue(asCheckedOut.isEmpty(),
                "NativeLengthCache held in a static:\n  " + String.join("\n  ", asCheckedOut));
    }

    /**
     * Outside the cache class and the NI interfaces, the cache appears only in
     * classes that implement the accessor, i.e. the NI implementations. An SPI
     * holding one, static or not, would cache beside its NI instead of in it.
     */
    @Test
    public void onlyTheNiImplementationsHoldTheCache() throws IOException
    {
        List<String> offenders = new ArrayList<String>();
        int implementations = 0;
        for (Map.Entry<Path, String> e : readTree().entrySet())
        {
            String code = stripComments(e.getValue());
            String name = e.getKey().getFileName().toString();
            if (!code.contains("NativeLengthCache") || name.equals("NativeLengthCache.java"))
            {
                continue;
            }
            if (code.matches("(?s).*\\binterface\\s+\\w+NI\\b.*"))
            {
                continue;
            }
            if (ACCESSOR.matcher(code).find())
            {
                implementations++;
                continue;
            }
            offenders.add(e.getKey().toString());
        }
        Assertions.assertTrue(offenders.isEmpty(),
                "NativeLengthCache used outside an NI implementation:\n  " + String.join("\n  ", offenders));
        Assertions.assertTrue(implementations > 0, "no NI implementation was recognised; the matcher reads nothing");
    }

    static String crlf(String text)
    {
        return text.replace("\r\n", "\n").replace("\n", "\r\n");
    }

    private static Map<Path, String> readTree() throws IOException
    {
        Path root = resolve();
        Assertions.assertNotNull(root, MAIN + " is not reachable from " + Paths.get("").toAbsolutePath());
        List<Path> sources;
        try (Stream<Path> walk = Files.walk(root))
        {
            sources = walk.filter(p -> p.getFileName().toString().endsWith(".java")).sorted()
                    .collect(Collectors.toList());
        }
        Assertions.assertTrue(sources.size() >= MIN_SOURCES,
                "only " + sources.size() + " sources under " + root + "; this scan is not reading the tree");
        Map<Path, String> texts = new LinkedHashMap<Path, String>();
        for (Path p : sources)
        {
            texts.put(root.relativize(p), new String(Files.readAllBytes(p), StandardCharsets.UTF_8));
        }
        return texts;
    }

    private static List<String> scan(Map<Path, String> texts)
    {
        List<String> out = new ArrayList<String>();
        for (Map.Entry<Path, String> e : texts.entrySet())
        {
            for (Integer line : staticSites(e.getValue()))
            {
                out.add(e.getKey() + ":" + line);
            }
        }
        return out;
    }

    /** Line numbers, 1-based, of each static cache declaration. */
    static List<Integer> staticSites(String text)
    {
        String code = stripComments(text);
        List<Integer> out = new ArrayList<Integer>();
        Matcher m = STATIC_CACHE.matcher(code);
        while (m.find())
        {
            int at = code.lastIndexOf("NativeLengthCache", m.end());
            out.add(code.substring(0, at).split("\r?\n", -1).length);
        }
        if (IS_INTERFACE.matcher(code).find())
        {
            Matcher f = INTERFACE_FIELD.matcher(code);
            while (f.find())
            {
                out.add(code.substring(0, f.start()).split("\r?\n", -1).length);
            }
        }
        return out;
    }

    /** Comments become spaces, line breaks kept, so line numbers survive. */
    static String stripComments(String text)
    {
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length())
        {
            char c = text.charAt(i);
            if (c == '"')
            {
                int j = i + 1;
                while (j < text.length() && text.charAt(j) != '"' && text.charAt(j) != '\n')
                {
                    j += text.charAt(j) == '\\' ? 2 : 1;
                }
                j = Math.min(j + 1, text.length());
                out.append(text, i, j);
                i = j;
            }
            else if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '*')
            {
                int end = text.indexOf("*/", i + 2);
                int stop = end < 0 ? text.length() : end + 2;
                for (int k = i; k < stop; k++)
                {
                    char ch = text.charAt(k);
                    out.append(ch == '\n' || ch == '\r' ? ch : ' ');
                }
                i = stop;
            }
            else if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '/')
            {
                while (i < text.length() && text.charAt(i) != '\n' && text.charAt(i) != '\r')
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

    private static Path resolve()
    {
        for (Path base : new Path[]{Paths.get(""), Paths.get(".."), Paths.get("jostle")})
        {
            Path p = base.resolve(MAIN);
            if (Files.isDirectory(p))
            {
                return p;
            }
        }
        Path alt = Paths.get("src/main");
        return Files.isDirectory(alt) ? alt : null;
    }
}
