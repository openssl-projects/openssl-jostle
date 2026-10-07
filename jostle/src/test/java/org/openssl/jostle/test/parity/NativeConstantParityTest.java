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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.OpenSSLNI;
import org.openssl.jostle.jcajce.provider.cert.X509NI;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every numeric constant Java mirrors from a C header carries the same value.
 *
 * <p>A mirrored constant is two sources of truth by construction — the project
 * cannot avoid that across a JNI boundary — so what makes it safe is a check
 * that they agree. Nothing else does: a slot index that drifts reads the wrong
 * field out of a correctly-built blob, and an error code that drifts maps a
 * refusal onto some other refusal's message. Both are silent.
 *
 * <p><b>Its inputs live under {@code interface/}, which is NOT a Gradle test
 * task input.</b> A run after editing only C is served from the cache and the
 * test does not execute — which reads exactly like it passing. Falsify with
 * {@code --rerun}.
 */
public class NativeConstantParityTest
{
    // A trailing comment is allowed: JO_SUCCESS, JO_FAIL and JO_UNKNOWN_OSSL_KEY_TYPE carry one.
    private static final Pattern C_DEFINE = Pattern.compile(
            "^#define\\s+(JO_[A-Z0-9_]+)\\s+\\(?(-?\\d+)\\)?\\s*(?:/\\*.*|//.*)?$", Pattern.MULTILINE);

    private static final String NONFIPS_CODES = "interface/nonfips/util/bc_err_codes.h";
    private static final String FIPS_CODES = "interface/fips/util/bc_err_codes.h";

    private static final String NONFIPS_CAPABILITY = "interface/nonfips/util/capability.h";
    private static final String FIPS_CAPABILITY = "interface/fips/util/capability.h";

    /** An alias of another define: {@code #define JO_A JO_B}, with an optional trailing comment. */
    private static final Pattern C_ALIAS = Pattern.compile(
            "^#define\\s+(JO_[A-Z0-9_]+)\\s+(JO_[A-Z0-9_]+)\\s*(?:/\\*.*|//.*)?$", Pattern.MULTILINE);

    /** Every #define JO_ line, whatever follows the name. */
    private static final Pattern ANY_JO_DEFINE = Pattern.compile("^#define\\s+(JO_[A-Za-z0-9_]+)\\b.*$",
            Pattern.MULTILINE);

    /** The only JO_ defines in the error-code headers that are not a numeric value. */
    private static final Set<String> NON_NUMERIC = new HashSet<>(
            java.util.Arrays.asList("JO_RAND_RESEED", "JO_ERROR_WAS_INJECTED"));

    /** Java's catch-all for a code no entry claims; no C header defines it. */
    private static final String JAVA_SENTINEL = "JO_UNKNOWN";

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

    private static String read(String relative) throws IOException
    {
        return new String(Files.readAllBytes(repoRoot().resolve(relative)), StandardCharsets.UTF_8);
    }

    private static Map<String, Integer> cDefines(String relative) throws IOException
    {
        String text = read(relative);
        Map<String, Integer> out = new TreeMap<>();
        Matcher m = C_DEFINE.matcher(text);
        while (m.find())
        {
            out.put(m.group(1), Integer.parseInt(m.group(2)));
        }
        return out;
    }

    private static Map<String, Integer> javaCodes()
    {
        Map<String, Integer> out = new TreeMap<>();
        for (ErrorCode code : ErrorCode.values())
        {
            if (!JAVA_SENTINEL.equals(code.name()))
            {
                out.put(code.name(), code.getCode());
            }
        }
        return out;
    }

    /**
     * Both C tables against ErrorCode, both ways: every code either tree defines (the FIPS tree's own codes
     * included) has a Java entry with its value, every Java entry is a code in at least one tree, and a name both
     * trees define has one value.
     */
    @Test
    public void errorCodesAgreeAcrossBothTreesAndJava() throws Exception
    {
        Map<String, Integer> base = cDefines(NONFIPS_CODES);
        Map<String, Integer> fips = cDefines(FIPS_CODES);
        Map<String, Integer> java = javaCodes();
        Assertions.assertTrue(base.size() > 100 && fips.size() > 100 && java.size() > 100,
                "read " + base.size() + " / " + fips.size() + " / " + java.size()
                        + " codes; a reader is not reading its source");

        StringBuilder bad = new StringBuilder();
        for (String name : new TreeSet<>(base.keySet()))
        {
            if (fips.containsKey(name) && !fips.get(name).equals(base.get(name)))
            {
                bad.append("\n  ").append(name).append(": nonfips ").append(base.get(name))
                   .append(" vs fips ").append(fips.get(name));
            }
        }
        Map<String, Integer> c = new TreeMap<>(fips);
        c.putAll(base);
        for (Map.Entry<String, Integer> e : c.entrySet())
        {
            Integer j = java.get(e.getKey());
            if (j == null)
            {
                bad.append("\n  ").append(e.getKey()).append(" (").append(e.getValue())
                   .append("): in C, no ErrorCode entry");
            }
            else if (!j.equals(e.getValue()))
            {
                bad.append("\n  ").append(e.getKey()).append(": C ").append(e.getValue())
                   .append(" vs Java ").append(j);
            }
        }
        for (Map.Entry<String, Integer> e : java.entrySet())
        {
            if (!c.containsKey(e.getKey()))
            {
                bad.append("\n  ").append(e.getKey()).append(" (").append(e.getValue())
                   .append("): an ErrorCode entry neither C table defines");
            }
        }
        Assertions.assertEquals(0, bad.length(), "error code tables disagree:" + bad);
    }

    /**
     * Every #define JO_ line in the error-code headers is one the reader above parses, or one of the allow-listed
     * non-numeric names. A define the reader cannot parse is a code the parity check silently skips.
     */
    @Test
    public void everyErrorCodeDefineIsRead() throws Exception
    {
        StringBuilder bad = new StringBuilder();
        for (String header : new String[]{NONFIPS_CODES, FIPS_CODES})
        {
            Map<String, Integer> parsed = cDefines(header);
            Matcher m = ANY_JO_DEFINE.matcher(read(header));
            int seen = 0;
            while (m.find())
            {
                seen++;
                String name = m.group(1);
                if (!parsed.containsKey(name) && !NON_NUMERIC.contains(name))
                {
                    bad.append("\n  ").append(header).append(": ").append(m.group(0));
                }
            }
            Assertions.assertTrue(seen > 100, header + ": saw only " + seen + " #define JO_ lines");
        }
        Assertions.assertEquals(0, bad.length(), "defines the parity reader does not parse:" + bad);
    }

    /**
     * The capability op types select which EVP fetch a probe makes; a drift sends every probe to the wrong one.
     * Both trees' headers, against OpenSSLNI. MIN and MAX are aliases and must name the ends of the range.
     */
    @Test
    public void capabilityOpTypesMatchTheHeader() throws Exception
    {
        Map<String, Integer> expected = new TreeMap<>();
        expected.put("JO_CAP_OP_KEYMGMT", OpenSSLNI.OP_KEYMGMT);
        expected.put("JO_CAP_OP_KEYEXCH", OpenSSLNI.OP_KEYEXCH);
        expected.put("JO_CAP_OP_SIGNATURE", OpenSSLNI.OP_SIGNATURE);
        expected.put("JO_CAP_OP_ASYM_CIPHER", OpenSSLNI.OP_ASYM_CIPHER);
        expected.put("JO_CAP_OP_MD", OpenSSLNI.OP_MD);
        expected.put("JO_CAP_OP_CIPHER", OpenSSLNI.OP_CIPHER);
        expected.put("JO_CAP_OP_KDF", OpenSSLNI.OP_KDF);
        expected.put("JO_CAP_OP_MAC", OpenSSLNI.OP_MAC);
        expected.put("JO_CAP_OP_RAND", OpenSSLNI.OP_RAND);

        for (String header : new String[]{NONFIPS_CAPABILITY, FIPS_CAPABILITY})
        {
            Map<String, Integer> numeric = cDefines(header);
            Assertions.assertEquals(expected, numeric, header + " op types drifted from OpenSSLNI");

            Map<String, String> aliases = new TreeMap<>();
            Matcher a = C_ALIAS.matcher(read(header));
            while (a.find())
            {
                aliases.put(a.group(1), a.group(2));
            }
            Map<String, String> bounds = new TreeMap<>();
            bounds.put("JO_CAP_OP_MAX", "JO_CAP_OP_RAND");
            bounds.put("JO_CAP_OP_MIN", "JO_CAP_OP_KEYMGMT");
            Assertions.assertEquals(bounds, aliases, header + " range bounds");

            Matcher m = ANY_JO_DEFINE.matcher(read(header));
            int seen = 0;
            while (m.find())
            {
                seen++;
                Assertions.assertTrue(numeric.containsKey(m.group(1)) || aliases.containsKey(m.group(1)),
                        header + ": unread define " + m.group(0));
            }
            Assertions.assertEquals(expected.size() + bounds.size(), seen, header + " define count");
        }
    }

    @Test
    public void theJavaSentinelIsNoCode() throws Exception
    {
        Map<String, Integer> c = new TreeMap<>(cDefines(FIPS_CODES));
        c.putAll(cDefines(NONFIPS_CODES));
        Assertions.assertFalse(c.containsKey(JAVA_SENTINEL), JAVA_SENTINEL + " is now a C code");
        Assertions.assertEquals(Integer.MIN_VALUE, ErrorCode.valueOf(JAVA_SENTINEL).getCode());
    }

    /**
     * The X.509 slot and info indices, and the certificate ceiling. These are
     * read positionally out of one blob, so a drift does not fail — it returns
     * a different field, which is the worst way for this to go wrong.
     */
    @Test
    public void x509SlotAndInfoIndicesMatchTheHeader() throws Exception
    {
        String text = new String(Files.readAllBytes(repoRoot().resolve("interface/nonfips/util/x509.h")),
                StandardCharsets.UTF_8);
        Map<String, Integer> c = new TreeMap<>();
        // Trailing /* ... */ comments are the norm on these defines, so the
        // pattern must stop at the value rather than anchor to end of line. The
        // first version anchored, matched 9 of 24, and the vacuity floor below
        // is what reported it rather than a clean sweep over a third of them.
        Matcher m = Pattern.compile("^#define\\s+(X509_[A-Z0-9_]+)\\s+\\(?([0-9][0-9*() ]*?)\\)?\\s*(?:/\\*.*)?$",
                Pattern.MULTILINE).matcher(text);
        while (m.find())
        {
            String v = m.group(2).trim();
            if (v.equals("1024 * 1024"))
            {
                c.put(m.group(1), 1024 * 1024);
            }
            else if (v.matches("\\d+"))
            {
                c.put(m.group(1), Integer.parseInt(v));
            }
        }
        Assertions.assertTrue(c.size() >= 20, "read only " + c.size() + " X509_ defines from x509.h");

        assertSame(c, "X509_SLOT_ENCODED", X509NI.SLOT_ENCODED);
        assertSame(c, "X509_SLOT_TBS", X509NI.SLOT_TBS);
        assertSame(c, "X509_SLOT_SERIAL", X509NI.SLOT_SERIAL);
        assertSame(c, "X509_SLOT_ISSUER", X509NI.SLOT_ISSUER);
        assertSame(c, "X509_SLOT_SUBJECT", X509NI.SLOT_SUBJECT);
        assertSame(c, "X509_SLOT_SIGNATURE", X509NI.SLOT_SIGNATURE);
        assertSame(c, "X509_SLOT_SIGALG_OID", X509NI.SLOT_SIGALG_OID);
        assertSame(c, "X509_SLOT_SIGALG_PARAMS", X509NI.SLOT_SIGALG_PARAMS);
        assertSame(c, "X509_SLOT_ISSUER_UID", X509NI.SLOT_ISSUER_UID);
        assertSame(c, "X509_SLOT_SUBJECT_UID", X509NI.SLOT_SUBJECT_UID);
        assertSame(c, "X509_SLOT_SPKI_ALG_OID", X509NI.SLOT_SPKI_ALG_OID);
        assertSame(c, "X509_SLOT_COUNT", X509NI.SLOT_COUNT);

        assertSame(c, "X509_INFO_VERSION", X509NI.INFO_VERSION);
        assertSame(c, "X509_INFO_NOT_BEFORE_HI", X509NI.INFO_NOT_BEFORE_HI);
        assertSame(c, "X509_INFO_NOT_BEFORE_LO", X509NI.INFO_NOT_BEFORE_LO);
        assertSame(c, "X509_INFO_NOT_AFTER_HI", X509NI.INFO_NOT_AFTER_HI);
        assertSame(c, "X509_INFO_NOT_AFTER_LO", X509NI.INFO_NOT_AFTER_LO);
        assertSame(c, "X509_INFO_BASIC_CONSTRAINTS", X509NI.INFO_BASIC_CONSTRAINTS);
        assertSame(c, "X509_INFO_KEY_USAGE_BITS", X509NI.INFO_KEY_USAGE_BITS);
        assertSame(c, "X509_INFO_KEY_USAGE_VALUE", X509NI.INFO_KEY_USAGE_VALUE);
        assertSame(c, "X509_INFO_ISSUER_UID_BITS", X509NI.INFO_ISSUER_UID_BITS);
        assertSame(c, "X509_INFO_SUBJECT_UID_BITS", X509NI.INFO_SUBJECT_UID_BITS);
        assertSame(c, "X509_INFO_EXT_COUNT", X509NI.INFO_EXT_COUNT);
        assertSame(c, "X509_INFO_COUNT", X509NI.INFO_COUNT);

        assertSame(c, "X509_DEFAULT_MAX_CERT_BYTES", X509NI.DEFAULT_MAX_CERT_BYTES);
    }

    private static void assertSame(Map<String, Integer> c, String name, int javaValue)
    {
        Integer cValue = c.get(name);
        Assertions.assertNotNull(cValue, name + " is not defined in x509.h");
        Assertions.assertEquals(cValue.intValue(), javaValue, name + " drifted between x509.h and X509NI");
    }
}
