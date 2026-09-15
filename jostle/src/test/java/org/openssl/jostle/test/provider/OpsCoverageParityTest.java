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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Every OPS fault-injection point in the C tree is DRIVEN by a test.
 *
 * <p>This is the parity direction the existing tooling does not check. The
 * {@code audit-openssl-ops-coverage} skill asks whether an OpenSSL call has an
 * OPS point; {@code FIPSOpsAnnotationParityTest} asks whether a FIPS test's
 * annotation names the right tree. Neither asks the question here: an
 * {@code OPS_*} macro added to C with no test driving it is a fault path that
 * exists, costs a branch, and has never been executed.
 *
 * <p><b>It is a RATCHET, not a clean sheet.</b> {@value #BASELINE_SIZE}
 * (file, flag) pairs are uncovered — measured, not
 * estimated, and overwhelmingly in the FIPS tree where several families have no
 * {@code FIPS*OpsTest} mirror at all. Sanctioning them silently would be the
 * exemption-list failure the guides warn about, so instead:
 *
 * <ul>
 *   <li>a NEW uncovered pair FAILS — the gap cannot grow;</li>
 *   <li>a baseline entry that has SINCE been covered also FAILS, naming itself,
 *       so the list shrinks as work lands and cannot outlive its reason. That
 *       is the ratchet, and it is the half an exemption list usually lacks.</li>
 * </ul>
 *
 * <p><b>Two instrument traps, both hit while writing this.</b> A path capture
 * of {@code interface/\S+} swallows the trailing comma in
 * {@code // Exercises …/x509.c, offset 7002}, and a flag pattern of
 * {@code OPS_[A-Z_]+_\d+} silently misses the whole {@code OPS_INT32_OVERFLOW}
 * family, because {@code INT32} contains digits. Both fail in the reassuring
 * direction, so the vacuity floors below are load-bearing rather than
 * decorative.
 *
 * <p><b>{@code interface/} is not a Gradle task input</b>, so a re-run after
 * editing C needs {@code --rerun} or this test will not execute at all — which
 * reads exactly like it passing.
 */
public class OpsCoverageParityTest
{
    /** Families are listed explicitly; {@code INT32} defeats a generic pattern. */
    private static final Pattern FLAG = Pattern.compile(
            "\\b(OPS_(?:FAILED_ACCESS|OPENSSL_ERROR|FAILED_CREATE|FAILED_INIT|FAILED_SET"
                    + "|LEN_CHANGE|INT32_OVERFLOW|SHORT_SIZE|ALTERNATE|THREAD_ATTACH"
                    + "|JNI_FAIL_CREATE)_\\d+|OPS_POINTER_CHANGE|OPS_RAND_UP_CALL_NULL)\\b");

    /** Stops at the extension, so trailing prose cannot join the path. */
    private static final Pattern EXERCISES = Pattern.compile(
            "//\\s*Exercises\\s+(interface/\\S*?\\.[ch])\\b");

    private static final Pattern SET_FLAG = Pattern.compile("OpsTestFlag\\.(\\w+)");

    /** Floors that make a broken matcher fail instead of reporting a clean tree. */
    private static final int MIN_PAIRS = 400;
    private static final int MIN_ANNOTATED_FILES = 50;

    static final int BASELINE_SIZE = 139;

    private static final Set<String> BASELINE = baseline();

    private static Set<String> baseline()
    {
        Set<String> s = new LinkedHashSet<String>();
        add(s, "interface/fips/ffi/asn1_ni_ffi.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/ffi/mac_ffi.c", "OPS_INT32_OVERFLOW_2");
        add(s, "interface/fips/ffi/md_ffi.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/ffi/rand_upcall_ffi.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/ffi/rand_upcall_ffi.c", "OPS_INT32_OVERFLOW_2");
        add(s, "interface/fips/ffi/rand_upcall_ffi.c", "OPS_RAND_UP_CALL_NULL");
        add(s, "interface/fips/ffi/rand_upcall_ffi.c", "OPS_SHORT_SIZE_1");
        add(s, "interface/fips/jni/block_cipher_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/block_cipher_ni_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/fips/jni/dh_ni_jni.c", "OPS_FAILED_ACCESS_4");
        add(s, "interface/fips/jni/ec_ni_jni.c", "OPS_FAILED_ACCESS_3");
        add(s, "interface/fips/jni/ec_ni_jni.c", "OPS_FAILED_ACCESS_4");
        add(s, "interface/fips/jni/ec_ni_jni.c", "OPS_FAILED_ACCESS_5");
        add(s, "interface/fips/jni/ed_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/ed_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/fips/jni/mac_jni.c", "OPS_FAILED_ACCESS_5");
        add(s, "interface/fips/jni/mldsa_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/mlkem_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/mlxkem_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/mlxkem_ni_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/fips/jni/mlxkem_ni_jni.c", "OPS_FAILED_ACCESS_3");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_FAILED_CREATE_1");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_INT32_OVERFLOW_2");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_RAND_UP_CALL_NULL");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_SHORT_SIZE_1");
        add(s, "interface/fips/jni/rand_upcall_jni.c", "OPS_THREAD_ATTACH_1");
        add(s, "interface/fips/jni/slhdsa_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/spec_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/jni/spec_ni_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/fips/jni/spec_ni_jni.c", "OPS_FAILED_ACCESS_3");
        add(s, "interface/fips/jni/xec_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/fips/util/asn1_util.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/asn1_util.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/block_cipher_ctx.c", "OPS_FAILED_SET_1");
        add(s, "interface/fips/util/block_cipher_ctx.c", "OPS_FAILED_SET_2");
        add(s, "interface/fips/util/block_cipher_ctx.c", "OPS_OPENSSL_ERROR_10");
        add(s, "interface/fips/util/block_cipher_ctx.c", "OPS_OPENSSL_ERROR_11");
        add(s, "interface/fips/util/block_cipher_ctx.c", "OPS_OPENSSL_ERROR_8");
        add(s, "interface/fips/util/dh.c", "OPS_FAILED_SET_1");
        add(s, "interface/fips/util/edec.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/util/edec.c", "OPS_LEN_CHANGE_1");
        add(s, "interface/fips/util/edec.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/edec.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/edec.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/edec.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/encapdecap.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/util/encapdecap.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/encapdecap.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/encapdecap.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/encapdecap.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/encapdecap.c", "OPS_OPENSSL_ERROR_5");
        add(s, "interface/fips/util/mac.c", "OPS_ALTERNATE_3");
        add(s, "interface/fips/util/mac.c", "OPS_OPENSSL_ERROR_7");
        add(s, "interface/fips/util/mac.c", "OPS_OPENSSL_ERROR_8");
        add(s, "interface/fips/util/mac.c", "OPS_OPENSSL_ERROR_9");
        add(s, "interface/fips/util/mldsa.c", "OPS_FAILED_CREATE_1");
        add(s, "interface/fips/util/mldsa.c", "OPS_FAILED_CREATE_2");
        add(s, "interface/fips/util/mldsa.c", "OPS_FAILED_INIT_1");
        add(s, "interface/fips/util/mldsa.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/util/mldsa.c", "OPS_LEN_CHANGE_1");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_10");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_11");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_12");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_5");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_6");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_7");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_8");
        add(s, "interface/fips/util/mldsa.c", "OPS_OPENSSL_ERROR_9");
        add(s, "interface/fips/util/mldsa.c", "OPS_SHORT_SIZE_1");
        add(s, "interface/fips/util/mlkem.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/util/mlkem.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/mlkem.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/mlkem.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/mlkem.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/mlkem.c", "OPS_OPENSSL_ERROR_5");
        add(s, "interface/fips/util/mlkem.c", "OPS_OPENSSL_ERROR_6");
        add(s, "interface/fips/util/mlxkem.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_5");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_6");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_7");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_8");
        add(s, "interface/fips/util/mlxkem.c", "OPS_OPENSSL_ERROR_9");
        add(s, "interface/fips/util/rand.c", "OPS_FAILED_INIT_2");
        add(s, "interface/fips/util/rsa_pkcs1.c", "OPS_FAILED_INIT_1");
        add(s, "interface/fips/util/rsa_pkcs1.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/slhdsa.c", "OPS_FAILED_CREATE_1");
        add(s, "interface/fips/util/slhdsa.c", "OPS_FAILED_CREATE_2");
        add(s, "interface/fips/util/slhdsa.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/util/slhdsa.c", "OPS_LEN_CHANGE_1");
        add(s, "interface/fips/util/slhdsa.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/slhdsa.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/slhdsa.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/slhdsa.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/fips/util/slhdsa.c", "OPS_OPENSSL_ERROR_5");
        add(s, "interface/fips/util/slhdsa.c", "OPS_OPENSSL_ERROR_6");
        add(s, "interface/fips/util/xec.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/fips/util/xec.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/fips/util/xec.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/fips/util/xec.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/nonfips/ffi/asn1_ni_ffi.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/nonfips/ffi/mac_ffi.c", "OPS_INT32_OVERFLOW_2");
        add(s, "interface/nonfips/ffi/md_ffi.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/nonfips/jni/block_cipher_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/nonfips/jni/block_cipher_ni_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/nonfips/jni/dh_ni_jni.c", "OPS_FAILED_ACCESS_4");
        add(s, "interface/nonfips/jni/ec_ni_jni.c", "OPS_FAILED_ACCESS_3");
        add(s, "interface/nonfips/jni/ec_ni_jni.c", "OPS_FAILED_ACCESS_4");
        add(s, "interface/nonfips/jni/ec_ni_jni.c", "OPS_FAILED_ACCESS_5");
        add(s, "interface/nonfips/jni/mac_jni.c", "OPS_FAILED_ACCESS_5");
        add(s, "interface/nonfips/jni/mlxkem_ni_jni.c", "OPS_FAILED_ACCESS_1");
        add(s, "interface/nonfips/jni/mlxkem_ni_jni.c", "OPS_FAILED_ACCESS_2");
        add(s, "interface/nonfips/jni/mlxkem_ni_jni.c", "OPS_FAILED_ACCESS_3");
        add(s, "interface/nonfips/util/edec.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/nonfips/util/mac.c", "OPS_OPENSSL_ERROR_8");
        add(s, "interface/nonfips/util/mac.c", "OPS_OPENSSL_ERROR_9");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_3");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_4");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_5");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_6");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_7");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_8");
        add(s, "interface/nonfips/util/mlxkem.c", "OPS_OPENSSL_ERROR_9");
        add(s, "interface/nonfips/util/rand.c", "OPS_FAILED_INIT_2");
        add(s, "interface/nonfips/util/rand/jostle_lib_ctx.c", "OPS_OPENSSL_ERROR_1");
        add(s, "interface/nonfips/util/rand/jostle_lib_ctx.c", "OPS_OPENSSL_ERROR_2");
        add(s, "interface/nonfips/util/rand/jostle_lib_ctx.c", "OPS_RAND_UP_CALL_NULL");
        return Collections.unmodifiableSet(s);
    }

    private static void add(Set<String> s, String file, String flag)
    {
        s.add(file + "  " + flag);
    }

    @Test
    public void everyOpsPointIsDrivenByATest() throws Exception
    {
        Path root = repoRoot();
        Assumptions.assumeTrue(root != null, "source tree not available");

        Map<String, Set<String>> sites = scanC(root);
        Map<String, Set<String>> driven = scanTests(root);

        int pairs = 0;
        for (Set<String> v : sites.values())
        {
            pairs += v.size();
        }
        Assertions.assertTrue(pairs >= MIN_PAIRS,
                "only " + pairs + " (file, flag) pairs found in the C tree — the flag pattern has"
                        + " drifted, and a zero-finding run would read as a clean tree");
        Assertions.assertTrue(driven.size() >= MIN_ANNOTATED_FILES,
                "only " + driven.size() + " annotated C paths found in the tests — the Exercises"
                        + " pattern has drifted");

        Set<String> uncovered = new TreeSet<String>();
        for (Map.Entry<String, Set<String>> e : sites.entrySet())
        {
            Set<String> hit = driven.get(e.getKey());
            for (String flag : e.getValue())
            {
                if (hit == null || !hit.contains(flag))
                {
                    uncovered.add(e.getKey() + "  " + flag);
                }
            }
        }

        List<String> appeared = new ArrayList<String>();
        for (String u : uncovered)
        {
            if (!BASELINE.contains(u))
            {
                appeared.add(u);
            }
        }
        List<String> fixed = new ArrayList<String>();
        for (String known : BASELINE)
        {
            if (!uncovered.contains(known))
            {
                fixed.add(known);
            }
        }

        Assertions.assertTrue(appeared.isEmpty(),
                "these OPS points are instrumented in C but no test drives them (" + appeared.size()
                        + "). An injection point nothing exercises is a branch that has never run:\n  "
                        + String.join("\n  ", appeared));

        Assertions.assertTrue(fixed.isEmpty(),
                "these baseline entries are now COVERED (" + fixed.size() + ") — delete them, so"
                        + " the list shrinks as the gap closes and cannot outlive its reason:\n  "
                        + String.join("\n  ", fixed));

        Assertions.assertEquals(BASELINE_SIZE, BASELINE.size(),
                "the baseline literal and its declared size disagree");
    }

    private static Map<String, Set<String>> scanC(Path root) throws IOException
    {
        Map<String, Set<String>> out = new LinkedHashMap<String, Set<String>>();
        for (String tree : new String[]{ "interface/nonfips", "interface/fips" })
        {
            Path base = root.resolve(tree);
            if (!Files.isDirectory(base))
            {
                continue;
            }
            Stream<Path> walk = Files.walk(base);
            try
            {
                for (Path p : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator)
                {
                    String name = p.getFileName().toString();
                    if (name.equals("ops.h") || !(name.endsWith(".c") || name.endsWith(".h")))
                    {
                        continue;
                    }
                    String rel = root.relativize(p).toString().replace('\\', '/');
                    String body = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                    Matcher m = FLAG.matcher(body);
                    while (m.find())
                    {
                        Set<String> s = out.get(rel);
                        if (s == null)
                        {
                            s = new TreeSet<String>();
                            out.put(rel, s);
                        }
                        s.add(m.group(1));
                    }
                }
            }
            finally
            {
                walk.close();
            }
        }
        return out;
    }

    private static Map<String, Set<String>> scanTests(Path root) throws IOException
    {
        Map<String, Set<String>> out = new LinkedHashMap<String, Set<String>>();
        Path base = root.resolve("jostle/src/test");
        Stream<Path> walk = Files.walk(base);
        try
        {
            for (Path p : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator)
            {
                if (!p.getFileName().toString().endsWith("OpsTest.java"))
                {
                    continue;
                }
                String body = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                Set<String> flags = new TreeSet<String>();
                Matcher f = SET_FLAG.matcher(body);
                while (f.find())
                {
                    flags.add(f.group(1));
                }
                Matcher e = EXERCISES.matcher(body);
                while (e.find())
                {
                    Set<String> s = out.get(e.group(1));
                    if (s == null)
                    {
                        s = new TreeSet<String>();
                        out.put(e.group(1), s);
                    }
                    s.addAll(flags);
                }
            }
        }
        finally
        {
            walk.close();
        }
        return out;
    }

    private static Path repoRoot()
    {
        Path p = Paths.get("").toAbsolutePath();
        for (int i = 0; i < 6 && p != null; i++)
        {
            if (Files.isDirectory(p.resolve("interface"))
                    && Files.isDirectory(p.resolve("jostle/src/test")))
            {
                return p;
            }
            p = p.getParent();
        }
        return null;
    }
}
