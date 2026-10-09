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
import java.util.Arrays;
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
 * <p><b>Coverage is credited per METHOD.</b> A {@code // Exercises <path>:<line>} annotation credits its C file
 * only with the flags the same method sets, so removing one cell's annotation uncovers that cell's pair. A method
 * that sets a flag carries an annotation, or the marker {@code // Exercises: no single site, <why>} when it drives
 * no one site by design; a flag-setting method with neither, and an annotation or marker in a method that sets no
 * flag, each fail naming the method.
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
                    + "|LEDGER_SKIP_FREE)_\\d+|OPS_POINTER_CHANGE|OPS_RAND_UP_CALL_NULL)\\b");

    /** Stops at the extension, so trailing prose cannot join the path. */
    private static final Pattern EXERCISES = Pattern.compile(
            "//\\s*Exercises\\s+(interface/\\S*?\\.[ch])\\b");

    private static final Pattern SET_FLAG = Pattern.compile("OpsTestFlag\\.(\\w+)");

    /** The fixed marker for a method that drives no single site by design. */
    private static final Pattern NO_SITE = Pattern.compile("//\\s*Exercises:\\s*no single site,\\s*\\S");

    private static final Pattern TYPE_DECL = Pattern.compile("\\b(?:class|interface|enum)\\s+(\\w+)");

    private static final Pattern CALL_NAME = Pattern.compile("(\\w+)\\s*\\(");

    /** Floors that make a broken matcher fail instead of reporting a clean tree. */
    private static final int MIN_PAIRS = 400;
    private static final int MIN_ANNOTATED_FILES = 50;

    static final int BASELINE_SIZE = 119;

    private static final Set<String> BASELINE = baseline();

    private static Set<String> baseline()
    {
        Set<String> s = new LinkedHashSet<String>();
        add(s, "interface/fips/ffm/md_ffm.c", "OPS_INT32_OVERFLOW_1");
        // The FIPS-tree upcall rows (rand_upcall_ffm.c and rand_upcall_jni.c) are unreachable by construction: the FIPS
        // lib ctx installs no bridge RAND, so nothing calls the upcall. The base attach-failure branch
        // (rand_upcall_jni.c, OPS_THREAD_ATTACH_1 on the detached path) is unreachable too, every draw running on an
        // attached Java thread; it has no row because its flag is shared with the attached-path check.
        add(s, "interface/fips/ffm/rand_upcall_ffm.c", "OPS_INT32_OVERFLOW_1");
        add(s, "interface/fips/ffm/rand_upcall_ffm.c", "OPS_INT32_OVERFLOW_2");
        add(s, "interface/fips/ffm/rand_upcall_ffm.c", "OPS_RAND_UP_CALL_NULL");
        add(s, "interface/fips/ffm/rand_upcall_ffm.c", "OPS_SHORT_SIZE_1");
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
        add(s, "interface/fips/jni/xec_ni_jni.c", "OPS_FAILED_ACCESS_1");
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
        add(s, "interface/nonfips/ffm/md_ffm.c", "OPS_INT32_OVERFLOW_1");
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
        List<String> unannotated = new ArrayList<String>();
        List<String> unflagged = new ArrayList<String>();
        Map<String, Set<String>> driven = scanTests(root, unannotated, unflagged);

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

        System.out.println("[ops-coverage] pairs=" + pairs + " uncovered=" + uncovered.size()
                + " baseline=" + BASELINE.size());

        Assertions.assertTrue(unannotated.isEmpty(),
                "these methods set an OPS flag with no Exercises annotation and no no-single-site marker ("
                        + unannotated.size() + "):\n  " + String.join("\n  ", unannotated));
        Assertions.assertTrue(unflagged.isEmpty(),
                "these methods carry an Exercises annotation or marker and set no OPS flag (" + unflagged.size()
                        + "):\n  " + String.join("\n  ", unflagged));

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

    /**
     * The scanner counts a flag only in code. A file annotated by a test that sets the same flag elsewhere would
     * hide a comment-only pair from the coverage check, so the stripping is pinned on its own.
     */
    @Test
    public void flagsInCommentsAndStringsAreNotScanned()
    {
        String src = "// OPS_FAILED_INIT_1 in a line comment\n"
                + "/* OPS_OPENSSL_ERROR_2 in a\n   block comment */\n"
                + "const char *s = \"OPS_SHORT_SIZE_1 in a string\";\n"
                + "// OPS_LEDGER_SKIP_FREE_1 in a comment\n"
                + "if (OPS_FAILED_ACCESS_1 p == NULL) {\n"
                + "if (OPS_LEDGER_SKIP_FREE_1 0) {\n";
        String stripped = stripCommentsAndStrings(src);

        Set<String> found = new TreeSet<String>();
        Matcher m = FLAG.matcher(stripped);
        while (m.find())
        {
            found.add(m.group(1));
        }
        Assertions.assertEquals(new TreeSet<String>(Arrays.asList("OPS_FAILED_ACCESS_1", "OPS_LEDGER_SKIP_FREE_1")),
                found);
        Assertions.assertEquals(src.split("\n", -1).length, stripped.split("\n", -1).length, "line breaks kept");
    }

    /**
     * Each method keeps its own annotations and flags: a sibling's flag, a nested type's method, a brace in a
     * literal or a comment, and an annotation above the method all land where they belong.
     */
    @Test
    public void annotationsAndFlagsAreAttributedPerMethod()
    {
        String src = "public class SampleOpsTest\n{\n"
                + "    @Test\n    public void annotated()\n    {\n"
                + "        // Exercises interface/nonfips/util/a.c:10\n"
                + "        String s = \"} {\";\n"
                + "        ops.setFlag(OpsTestFlag.OPS_FAILED_INIT_1);\n    }\n\n"
                + "    // Exercises interface/nonfips/util/b.c:20\n"
                + "    @Test\n    public void annotatedAbove()\n    {\n"
                + "        run(OpsTestFlag.OPS_OPENSSL_ERROR_2, -1001);\n    }\n\n"
                + "    @Test\n    public void bare()\n    {\n"
                + "        // a comment with a brace {\n"
                + "        ops.setFlag(OpsTestFlag.OPS_SHORT_SIZE_1);\n    }\n\n"
                + "    @Test\n    public void marked()\n    {\n"
                + "        // Exercises: no single site, a reason here\n"
                + "        ops.setFlag(OpsTestFlag.OPS_OPENSSL_ERROR_3);\n    }\n\n"
                + "    static class Inner\n    {\n"
                + "        void innerCell()\n        {\n"
                + "            // Exercises interface/nonfips/util/c.c:30\n        }\n    }\n}\n";

        Map<String, Cell> byName = new LinkedHashMap<String, Cell>();
        for (Cell c : cells(src))
        {
            byName.put(c.name, c);
        }
        Assertions.assertEquals(Arrays.asList("SampleOpsTest.annotated", "SampleOpsTest.annotatedAbove",
                "SampleOpsTest.bare", "SampleOpsTest.marked", "SampleOpsTest.Inner.innerCell"),
                new ArrayList<String>(byName.keySet()));

        Cell annotated = byName.get("SampleOpsTest.annotated");
        Assertions.assertEquals(Collections.singletonList("interface/nonfips/util/a.c"), annotated.paths);
        Assertions.assertEquals(Collections.singleton("OPS_FAILED_INIT_1"), annotated.flags);

        Cell above = byName.get("SampleOpsTest.annotatedAbove");
        Assertions.assertEquals(Collections.singletonList("interface/nonfips/util/b.c"), above.paths);
        Assertions.assertEquals(Collections.singleton("OPS_OPENSSL_ERROR_2"), above.flags);

        Cell bare = byName.get("SampleOpsTest.bare");
        Assertions.assertTrue(bare.paths.isEmpty() && !bare.marked);
        Assertions.assertEquals(Collections.singleton("OPS_SHORT_SIZE_1"), bare.flags);

        Cell marked = byName.get("SampleOpsTest.marked");
        Assertions.assertTrue(marked.marked && marked.paths.isEmpty());

        Cell inner = byName.get("SampleOpsTest.Inner.innerCell");
        Assertions.assertEquals(Collections.singletonList("interface/nonfips/util/c.c"), inner.paths);
        Assertions.assertTrue(inner.flags.isEmpty());
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
                    String body = stripCommentsAndStrings(
                            new String(Files.readAllBytes(p), StandardCharsets.UTF_8));
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

    /**
     * Blanks C comments and string and character literals, keeping line breaks. A flag named in a comment is not
     * an injection point, and counting one put a pair in the baseline that no code could ever cover.
     */
    static String stripCommentsAndStrings(String src)
    {
        StringBuilder out = new StringBuilder(src.length());
        int i = 0;
        int n = src.length();
        while (i < n)
        {
            char c = src.charAt(i);
            if (c == '/' && i + 1 < n && src.charAt(i + 1) == '/')
            {
                while (i < n && src.charAt(i) != '\n')
                {
                    out.append(' ');
                    i++;
                }
            }
            else if (c == '/' && i + 1 < n && src.charAt(i + 1) == '*')
            {
                int end = src.indexOf("*/", i + 2);
                end = end < 0 ? n : end + 2;
                for (; i < end; i++)
                {
                    out.append(src.charAt(i) == '\n' ? '\n' : ' ');
                }
            }
            else if (c == '"' || c == '\'')
            {
                out.append(' ');
                i++;
                while (i < n && src.charAt(i) != c && src.charAt(i) != '\n')
                {
                    if (src.charAt(i) == '\\' && i + 1 < n)
                    {
                        out.append(' ');
                        i++;
                    }
                    out.append(' ');
                    i++;
                }
                if (i < n && src.charAt(i) == c)
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

    private static Map<String, Set<String>> scanTests(Path root, List<String> unannotated, List<String> unflagged)
            throws IOException
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
                for (Cell c : cells(body))
                {
                    if (c.flags.isEmpty())
                    {
                        if (!c.paths.isEmpty() || c.marked)
                        {
                            unflagged.add(c.name);
                        }
                        continue;
                    }
                    if (c.paths.isEmpty() && !c.marked)
                    {
                        unannotated.add(c.name + " " + c.flags);
                    }
                    for (String path : c.paths)
                    {
                        Set<String> s = out.get(path);
                        if (s == null)
                        {
                            s = new TreeSet<String>();
                            out.put(path, s);
                        }
                        s.addAll(c.flags);
                    }
                }
            }
        }
        finally
        {
            walk.close();
        }
        return out;
    }

    /** One member of a test class: the annotations and marker above and inside it, and the flags its code names. */
    static final class Cell
    {
        final String name;
        final List<String> paths = new ArrayList<String>();
        final Set<String> flags = new TreeSet<String>();
        boolean marked;

        Cell(String name)
        {
            this.name = name;
        }
    }

    /**
     * Splits a Java source into its members, nested types walked into, each carrying the comment text from the end
     * of the previous member to its own closing brace. Braces are matched on the stripped text, so a brace in a
     * comment or a literal does not move a boundary.
     */
    static List<Cell> cells(String src)
    {
        List<Cell> out = new ArrayList<Cell>();
        String code = stripCommentsAndStrings(src);
        Matcher top = TYPE_DECL.matcher(code);
        if (!top.find())
        {
            return out;
        }
        int open = code.indexOf('{', top.end());
        if (open < 0)
        {
            return out;
        }
        members(src, code, open + 1, matching(code, open), top.group(1) + ".", out);
        return out;
    }

    private static void members(String src, String code, int lo, int hi, String prefix, List<Cell> out)
    {
        int start = lo;
        int i = lo;
        while (i < hi)
        {
            char c = code.charAt(i);
            if (c == '{')
            {
                int close = matching(code, i);
                String header = code.substring(start, i);
                Matcher type = TYPE_DECL.matcher(header);
                if (type.find())
                {
                    members(src, code, i + 1, close, prefix + type.group(1) + ".", out);
                }
                else
                {
                    String name = "<init>";
                    Matcher call = CALL_NAME.matcher(header);
                    while (call.find())
                    {
                        name = call.group(1);
                    }
                    Cell cell = new Cell(prefix + name);
                    String raw = src.substring(start, close + 1);
                    Matcher e = EXERCISES.matcher(raw);
                    while (e.find())
                    {
                        cell.paths.add(e.group(1));
                    }
                    cell.marked = NO_SITE.matcher(raw).find();
                    Matcher f = SET_FLAG.matcher(code.substring(start, close + 1));
                    while (f.find())
                    {
                        cell.flags.add(f.group(1));
                    }
                    out.add(cell);
                }
                i = close + 1;
                start = i;
                continue;
            }
            if (c == ';' || c == '}')
            {
                start = i + 1;
            }
            i++;
        }
    }

    private static int matching(String code, int open)
    {
        int depth = 0;
        for (int i = open; i < code.length(); i++)
        {
            char c = code.charAt(i);
            if (c == '{')
            {
                depth++;
            }
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }
        return code.length() - 1;
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
