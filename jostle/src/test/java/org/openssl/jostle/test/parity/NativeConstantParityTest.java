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
import org.openssl.jostle.jcajce.provider.cert.X509NI;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
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
    private static final Pattern C_DEFINE =
            Pattern.compile("^#define\\s+(JO_[A-Z0-9_]+)\\s+\\(?(-?\\d+)\\)?\\s*$", Pattern.MULTILINE);

    /**
     * C codes with no {@link ErrorCode} entry, each because nothing in Java
     * has ever had to name it. Listed rather than tolerated silently, and
     * guarded below so an entry cannot outlive its reason.
     */
    private static final TreeSet<String> UNMAPPED_IN_JAVA = new TreeSet<>(java.util.Arrays.asList(
            "JO_VALUE_EXCEEDS_INT_MAX",
            "JO_KEY_SPEC_IS_NULL"));

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

    private static Map<String, Integer> cDefines(String relative) throws IOException
    {
        String text = new String(Files.readAllBytes(repoRoot().resolve(relative)), StandardCharsets.UTF_8);
        Map<String, Integer> out = new TreeMap<>();
        Matcher m = C_DEFINE.matcher(text);
        while (m.find())
        {
            out.put(m.group(1), Integer.parseInt(m.group(2)));
        }
        return out;
    }

    @Test
    public void everyErrorCodeJavaNamesCarriesItsCValue() throws Exception
    {
        Map<String, Integer> c = cDefines("interface/nonfips/util/bc_err_codes.h");
        Assertions.assertTrue(c.size() > 100,
                "read only " + c.size() + " defines; the matcher is not reading the header");

        int compared = 0;
        StringBuilder bad = new StringBuilder();
        for (Map.Entry<String, Integer> e : c.entrySet())
        {
            ErrorCode code;
            try
            {
                code = ErrorCode.valueOf(e.getKey());
            }
            catch (IllegalArgumentException absent)
            {
                continue;
            }
            compared++;
            if (code.getCode() != e.getValue())
            {
                bad.append("\n  ").append(e.getKey())
                   .append(": C ").append(e.getValue())
                   .append(" vs Java ").append(code.getCode());
            }
        }
        // Vacuity: a matcher that resolved nothing would report a clean sweep.
        Assertions.assertTrue(compared > 100, "compared only " + compared + " codes");
        Assertions.assertEquals(0, bad.length(), "error code value drift:" + bad);
    }

    @Test
    public void theUnmappedListIsStillAccurate() throws Exception
    {
        Map<String, Integer> c = cDefines("interface/nonfips/util/bc_err_codes.h");
        for (String name : UNMAPPED_IN_JAVA)
        {
            Assertions.assertTrue(c.containsKey(name),
                    name + " is no longer defined in C; drop it from UNMAPPED_IN_JAVA");
            boolean present;
            try
            {
                ErrorCode.valueOf(name);
                present = true;
            }
            catch (IllegalArgumentException absent)
            {
                present = false;
            }
            Assertions.assertFalse(present,
                    name + " now HAS an ErrorCode entry; drop it from UNMAPPED_IN_JAVA");
        }
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
