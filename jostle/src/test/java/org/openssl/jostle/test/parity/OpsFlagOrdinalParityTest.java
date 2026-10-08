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
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.ops.OperationsTestNI.LedgerType;
import org.openssl.jostle.util.ops.OperationsTestNI.OpsTestFlag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The operations-test flag slots and ledger types in ops.h equal the Java enum ordinals by name, in both trees.
 * The ordinal is the native index, so a drift sets one fault while the test believes it set another, and the
 * ledger reads one type's counts under another's name. Both are silent.
 *
 * <p>Its inputs live under {@code interface/}, which is not a Gradle test task input: falsify with
 * {@code --rerun}.
 */
public class OpsFlagOrdinalParityTest
{
    private static final String[] HEADERS = {"interface/nonfips/util/ops.h", "interface/fips/util/ops.h"};

    private static final Pattern FLAG = Pattern.compile(
            "^#define\\s+(OPS_[A-Z0-9_]+)\\s+!?is_ops_set\\((\\d+)\\)\\s*(?:\\|\\||&&)\\s*$", Pattern.MULTILINE);

    private static final Pattern OFFSET = Pattern.compile(
            "^#define\\s+OPS_OFFSET_([A-Z0-9_]+)\\(x\\)\\s+\\+\\s*\\(is_ops_set\\((\\d+)\\)", Pattern.MULTILINE);

    private static final Pattern MAX = Pattern.compile("^#define\\s+OPS_MAX_TEST\\s+(\\d+)\\s*$", Pattern.MULTILINE);

    private static final Pattern ANY_SLOT = Pattern.compile("is_ops_set\\(\\d+\\)");

    private static final Pattern LEDGER_ENUM = Pattern.compile("typedef enum jo_ledger_type\\s*\\{(.*?)\\}",
            Pattern.DOTALL);

    @Test
    public void everyFlagSlotEqualsItsJavaOrdinal() throws Exception
    {
        for (String header : HEADERS)
        {
            String text = stripComments(read(header));
            Map<String, Integer> c = new TreeMap<String, Integer>();
            Matcher m = FLAG.matcher(text);
            while (m.find())
            {
                Assertions.assertNull(c.put(m.group(1), Integer.parseInt(m.group(2))),
                        header + ": " + m.group(1) + " defined twice");
            }
            Assertions.assertTrue(c.size() >= 30, header + ": read only " + c.size() + " flag macros");

            Map<String, Integer> java = new TreeMap<String, Integer>();
            for (OpsTestFlag f : OpsTestFlag.values())
            {
                java.put(f.name(), f.ordinal());
            }
            Assertions.assertEquals(java, c, header + ": flag slots differ from OpsTestFlag ordinals");

            Matcher max = MAX.matcher(text);
            Assertions.assertTrue(max.find(), header + ": no OPS_MAX_TEST");
            Assertions.assertEquals(OpsTestFlag.values().length, Integer.parseInt(max.group(1)),
                    header + ": OPS_MAX_TEST");

            // Every slot use in the header is a flag or an offset this test reads.
            Map<String, Integer> offsets = offsets(text);
            Matcher any = ANY_SLOT.matcher(text);
            int slots = 0;
            while (any.find())
            {
                slots++;
            }
            Assertions.assertEquals(c.size() + offsets.size(), slots, header + ": unread is_ops_set uses");
        }
    }

    /** An offset macro scales its own flag's code, so it reads the same slot as that flag. */
    @Test
    public void everyOffsetReadsItsFlagSlot() throws Exception
    {
        for (String header : HEADERS)
        {
            Map<String, Integer> offsets = offsets(stripComments(read(header)));
            Assertions.assertTrue(offsets.size() >= 10, header + ": read only " + offsets.size() + " offsets");
            List<String> bad = new ArrayList<String>();
            for (Map.Entry<String, Integer> e : offsets.entrySet())
            {
                OpsTestFlag f;
                try
                {
                    f = OpsTestFlag.valueOf("OPS_" + e.getKey());
                }
                catch (IllegalArgumentException ex)
                {
                    bad.add("OPS_OFFSET_" + e.getKey() + ": no flag of that name");
                    continue;
                }
                if (f.ordinal() != e.getValue())
                {
                    bad.add("OPS_OFFSET_" + e.getKey() + " reads " + e.getValue() + ", its flag is " + f.ordinal());
                }
            }
            Assertions.assertTrue(bad.isEmpty(), header + ": " + bad);
        }
    }

    @Test
    public void everyLedgerTypeEqualsItsJavaOrdinal() throws Exception
    {
        for (String header : HEADERS)
        {
            Matcher m = LEDGER_ENUM.matcher(stripComments(read(header)));
            Assertions.assertTrue(m.find(), header + ": no jo_ledger_type");
            Map<String, Integer> c = new LinkedHashMap<String, Integer>();
            int next = 0;
            for (String entry : m.group(1).split(","))
            {
                String e = entry.trim();
                if (e.isEmpty())
                {
                    continue;
                }
                int eq = e.indexOf('=');
                if (eq >= 0)
                {
                    next = Integer.parseInt(e.substring(eq + 1).trim());
                    e = e.substring(0, eq).trim();
                }
                Assertions.assertTrue(e.startsWith("JO_LEDGER_"), header + ": unexpected entry " + e);
                c.put(e.substring("JO_LEDGER_".length()), next++);
            }
            Assertions.assertEquals(Integer.valueOf(LedgerType.values().length), c.remove("TYPES"),
                    header + ": JO_LEDGER_TYPES");

            Map<String, Integer> java = new LinkedHashMap<String, Integer>();
            for (LedgerType t : LedgerType.values())
            {
                java.put(t.name(), t.ordinal());
            }
            Assertions.assertTrue(java.size() >= 20, "read only " + java.size() + " ledger types");
            Assertions.assertEquals(java, c, header + ": ledger types differ from LedgerType ordinals");
        }
    }

    private static Map<String, Integer> offsets(String text)
    {
        Map<String, Integer> out = new TreeMap<String, Integer>();
        Matcher m = OFFSET.matcher(text);
        while (m.find())
        {
            out.put(m.group(1), Integer.parseInt(m.group(2)));
        }
        return out;
    }

    /** Blanks C comments, keeping line breaks, so a commented-out define is not read. */
    private static String stripComments(String src)
    {
        StringBuilder out = new StringBuilder(src.length());
        int i = 0;
        int n = src.length();
        while (i < n)
        {
            if (src.startsWith("//", i))
            {
                while (i < n && src.charAt(i) != '\n')
                {
                    i++;
                }
            }
            else if (src.startsWith("/*", i))
            {
                int end = src.indexOf("*/", i + 2);
                end = end < 0 ? n : end + 2;
                for (; i < end; i++)
                {
                    if (src.charAt(i) == '\n')
                    {
                        out.append('\n');
                    }
                }
            }
            else
            {
                out.append(src.charAt(i));
                i++;
            }
        }
        return out.toString().replace("\r", "");
    }

    private static String read(String relative) throws IOException
    {
        Path p = Paths.get("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("interface")))
        {
            p = p.getParent();
        }
        Assertions.assertNotNull(p, "could not locate the repository root from " + Paths.get("").toAbsolutePath());
        return new String(Files.readAllBytes(p.resolve(relative)), StandardCharsets.UTF_8);
    }
}
