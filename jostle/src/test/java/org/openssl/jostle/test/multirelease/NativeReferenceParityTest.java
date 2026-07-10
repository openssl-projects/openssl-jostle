/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.multirelease;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Source-level parity guard for the multi-release native-reference pattern.
 *
 * <p>A class that holds a native handle (a {@code NativeReference}) and makes
 * native calls under {@code synchronized(this)} in the Java 8 baseline
 * ({@code src/main/java}) keeps the handle reachable across the call via the
 * monitor. JDK 9+ replaces that with {@code Reference.reachabilityFence(this)}
 * inside {@code try/finally} in a {@code src/main/javaN/} override (see
 * java-spi.md, "Native references must outlive every JNI/FFI call"). The
 * baseline-only form is still <em>correct</em> -- the monitor keeps {@code this}
 * reachable on JDK 9+ too -- but it silently drifts from every peer SPI, and on
 * JDK 9+ the multi-release jar then serves the monitor-based class instead of
 * the intended fence.
 *
 * <p>The compiler cannot catch a missing override, so this is the guard. For
 * every baseline class that uses {@code synchronized (this)} together with a
 * {@code NativeReference} (or a {@code getReference()} call), it asserts a
 * multi-release override exists at some {@code src/main/javaN/} path and that
 * the override uses {@code reachabilityFence}. It was added after
 * {@code RSAPKCS1CipherSpi}, {@code RSAOAEPCipherSpi} and {@code KSServiceSPI}
 * were each found shipping baseline-only.
 *
 * <p>The check needs the source tree. When the suite is run from a packaged test
 * jar with no sources nearby, there is nothing to analyse, so the test
 * <em>skips</em> (a lint with nothing to lint) rather than failing.
 */
public class NativeReferenceParityTest
{
    // Override source sets, in ascending JDK order. A class first expressible at
    // a higher level (e.g. the EdEC key classes, which implement JDK-15 EdEC
    // interfaces) carries its fence override at that level rather than java9.
    private static final String[] OVERRIDE_DIRS =
            {"java9", "java11", "java15", "java17", "java21", "java25"};

    private static final Pattern SYNCHRONIZED_THIS =
            Pattern.compile("synchronized\\s*\\(\\s*this\\s*\\)");

    @Test
    public void everyNativeReferenceClassHasAFenceOverride()
        throws IOException
    {
        Path mainJava = findMainJava();
        Assumptions.assumeTrue(mainJava != null,
                "src/main/java is not reachable from the working directory ("
                        + Paths.get("").toAbsolutePath() + ") -- this guard is a source-level "
                        + "lint, so when the tests run from a packaged test jar with no source "
                        + "tree nearby there is nothing to check and the test is skipped, not failed");

        List<Path> sources;
        try (Stream<Path> walk = Files.walk(mainJava))
        {
            sources = walk.filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());
        }

        List<String> violations = new ArrayList<String>();
        for (Path source : sources)
        {
            String body = read(source);
            if (!SYNCHRONIZED_THIS.matcher(body).find())
            {
                continue;
            }
            // "getReference()" catches an inline handle access; "NativeReference"
            // a Ref field; "ASN1Encoder." a helper-delegated native encode where
            // the handle never appears literally in the class (the JORSA*Key
            // blind spot: getEncoded synchronized(this) but passes spec to the
            // encoder, so neither of the first two strings is present).
            if (!body.contains("NativeReference") && !body.contains("getReference()")
                    && !body.contains("ASN1Encoder."))
            {
                continue;
            }

            String rel = mainJava.relativize(source).toString();
            if (!hasFenceOverride(mainJava, rel))
            {
                violations.add(rel);
            }
        }

        Assertions.assertTrue(violations.isEmpty(),
                "Baseline classes that hold a native reference under synchronized(this) but lack a "
                        + "javaN/ Reference.reachabilityFence(this) override (see java-spi.md, "
                        + "\"Native references must outlive every JNI/FFI call\"): " + violations);
    }

    private static boolean hasFenceOverride(Path mainJava, String rel)
        throws IOException
    {
        for (String dir : OVERRIDE_DIRS)
        {
            Path twin = mainJava.resolveSibling(dir).resolve(rel);
            if (Files.exists(twin) && read(twin).contains("reachabilityFence"))
            {
                return true;
            }
        }
        return false;
    }

    // An SPI's OWN native handle (`<field>ref.getReference()`, the RefWrapper
    // field convention — `ref`, `signerRef`, etc.) passed as a CALL ARGUMENT
    // (preceded by '(' or ','). Scoped to the *-ref receiver on purpose: this
    // guards the disposal-daemon use-after-free on an SPI's own handle (the class
    // of the ML-DSA engineUpdate bug). It deliberately does NOT cover
    // `spec.getReference()` / `key.getReference()` — there the native handle
    // belongs to a caller-held key/spec kept reachable via synchronized(spec)
    // (see RSAComponents), a separate lower-risk pattern. Excludes the
    // `+ ref.getReference()` string-concatenation in toString().
    private static final Pattern GET_REFERENCE_ARG =
            Pattern.compile("[(,]\\s*(?:this\\.)?\\w*[Rr]ef\\.getReference\\s*\\(\\s*\\)");

    /**
     * Per-method strengthening of {@link #everyNativeReferenceClassHasAFenceOverride()}.
     * That guard is file-granular — it only checks that a class holding a native
     * handle has <em>a</em> fence override somewhere, so it misses a single
     * native-calling method that lacks a reachability guard while its siblings in
     * the same file carry one (the ML-DSA {@code engineUpdate} use-after-free:
     * every other method was guarded, so the file-level check passed).
     *
     * <p>This check is per-method: in every {@code src/main/java} baseline class,
     * any method that passes its own native handle ({@code <field>.getReference()})
     * as an argument to a native call must keep {@code this} reachable across that
     * call — via {@code synchronized(this)} (a {@code synchronized (this)} block or
     * a {@code synchronized} method modifier), an explicit
     * {@code Reference.reachabilityFence(this)}, or the terminal-op {@code reInit()}
     * pattern (a guaranteed call on {@code this} in a {@code finally} after the
     * native op). {@code private} helpers are exempt: they run under a
     * synchronized caller (e.g. {@code macLength()}, {@code initSignInternal()},
     * {@code RandServiceSPI.contextRandomBytes()}).
     */
    @Test
    public void everyOwnHandleNativeCallIsReachabilityGuarded()
        throws IOException
    {
        Path mainJava = findMainJava();
        Assumptions.assumeTrue(mainJava != null,
                "src/main/java not reachable (packaged test jar) — source lint skipped");

        List<Path> sources;
        try (Stream<Path> walk = Files.walk(mainJava))
        {
            sources = walk.filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());
        }

        List<String> violations = new ArrayList<String>();
        for (Path source : sources)
        {
            String raw = read(source);
            if (!raw.contains("getReference()"))
            {
                continue;
            }
            String body = stripComments(raw);
            List<int[]> syncThis = synchronizedThisRanges(body);
            for (Method m : methods(body))
            {
                if (m.modifiers.contains("private"))
                {
                    continue;
                }
                boolean methodGuarded = m.modifiers.contains("synchronized")
                        || m.text.contains("reachabilityFence")
                        || m.text.contains("reInit(");
                java.util.regex.Matcher gr = GET_REFERENCE_ARG.matcher(body);
                while (gr.find())
                {
                    int pos = gr.start();
                    if (pos < m.bodyStart || pos >= m.bodyEnd)
                    {
                        continue;
                    }
                    boolean callGuarded = methodGuarded || inAnyRange(syncThis, pos);
                    if (!callGuarded)
                    {
                        int line = 1 + (int) body.substring(0, pos).chars().filter(c -> c == '\n').count();
                        violations.add(mainJava.relativize(source) + ":" + m.name + " (~line " + line + ")");
                    }
                }
            }
        }

        Assertions.assertTrue(violations.isEmpty(),
                "Non-private methods passing their own native handle (<field>.getReference()) to a native call "
                        + "WITHOUT keeping `this` reachable (synchronized(this) / reachabilityFence(this) / trailing "
                        + "reInit()) — a use-after-free the file-level guard misses (see java-spi.md, \"Native "
                        + "references must outlive every JNI/FFI call\"): " + violations);
    }

    // A PKEYKeySpec held in an instance FIELD (not a local/parameter). The `;`
    // terminator (with no `=`) distinguishes a field declaration from an
    // initialised local (`PKEYKeySpec spec = ...;`), so method-local specs in
    // the KeyFactories / KeyGenerators are not mistaken for fields.
    private static final Pattern PKEYSPEC_FIELD =
            Pattern.compile("(?:private|protected|public|final|static|\\s)+PKEYKeySpec\\s+(\\w+)\\s*;");
    // ASN1Encoder encode entry points (as*) read the spec natively but do NOT
    // fence it — the caller must (see ASN1Encoder.asPrivateKeyInfo). The decode
    // side (from*) allocates a fresh spec and is not a call on a held handle.
    private static final Pattern ASN1_ENCODE_CALL =
            Pattern.compile("ASN1Encoder\\.as\\w+\\s*\\(");
    // A field spec's handle passed as a CALL ARGUMENT (preceded by '(' or ','),
    // i.e. handed to a native call — NOT a bare `return spec.getReference()`
    // accessor (AsymmetricKeyImpl.getReference), which only yields the handle to
    // a caller who owns the reachability obligation. Mirrors GET_REFERENCE_ARG.
    private static final Pattern ANY_GET_REFERENCE =
            Pattern.compile("[(,]\\s*((?:this\\.)?\\w+)\\.getReference\\s*\\(\\s*\\)");

    /**
     * Field-held-handle counterpart of {@link #everyOwnHandleNativeCallIsReachabilityGuarded()},
     * which is scoped to an SPI's own {@code *ref} handle. A KEY class (extends
     * {@code AsymmetricKeyImpl}, so it inherits the {@code spec} field) or a cipher
     * SPI that stores a {@code PKEYKeySpec} in a field makes native calls on that
     * <em>field</em> handle either inline ({@code <field>.getReference()}) or by
     * handing the field spec to {@code ASN1Encoder} (which reads it natively but
     * does not fence it). Every such non-private method must keep {@code this}
     * reachable across the call — {@code synchronized(this)} in the baseline (a
     * {@code javaN/} override then swaps in {@code reachabilityFence}). This is the
     * ML-KEM / ML-DSA / SLH-DSA key + ML-KEM KTS use-after-free that the
     * {@code *ref}-scoped check above did not cover.
     *
     * <p>Local-/parameter-held specs are exempt: {@link PKEYSPEC_FIELD} matches
     * only field declarations (so the KeyFactory / KeyGenerator locals and the
     * {@code ASN1Encoder} parameters are not flagged), and a receiver shadowed by
     * a method-local declaration is skipped.
     */
    @Test
    public void everyFieldHeldHandleNativeCallIsGuarded()
        throws IOException
    {
        Path mainJava = findMainJava();
        Assumptions.assumeTrue(mainJava != null,
                "src/main/java not reachable (packaged test jar) — source lint skipped");

        List<Path> sources;
        try (Stream<Path> walk = Files.walk(mainJava))
        {
            sources = walk.filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());
        }

        List<String> violations = new ArrayList<String>();
        for (Path source : sources)
        {
            String raw = read(source);
            if (!raw.contains("getReference()") && !raw.contains("ASN1Encoder."))
            {
                continue;
            }
            String body = stripComments(raw);

            boolean isKeyClass = body.contains("extends AsymmetricKeyImpl");
            Set<String> fieldSpecs = new HashSet<String>();
            if (isKeyClass)
            {
                // spec is declared in AsymmetricKeyImpl, inherited by every key class.
                fieldSpecs.add("spec");
            }
            Matcher fm = PKEYSPEC_FIELD.matcher(body);
            while (fm.find())
            {
                fieldSpecs.add(fm.group(1));
            }
            if (fieldSpecs.isEmpty())
            {
                continue;
            }

            List<int[]> syncRanges = synchronizedThisRanges(body);
            for (Method m : methods(body))
            {
                if (m.modifiers.contains("private"))
                {
                    continue;
                }
                boolean methodGuarded = m.modifiers.contains("synchronized")
                        || m.text.contains("reachabilityFence");

                List<Integer> sites = new ArrayList<Integer>();
                Matcher gr = ANY_GET_REFERENCE.matcher(body);
                while (gr.find())
                {
                    if (gr.start() < m.bodyStart || gr.start() >= m.bodyEnd)
                    {
                        continue;
                    }
                    String recv = gr.group(1).replace("this.", "");
                    if (!fieldSpecs.contains(recv))
                    {
                        continue;
                    }
                    // A method-local of the same name shadows the field and keeps
                    // the handle reachable on its own — not a field-handle call.
                    if (Pattern.compile("\\b\\w[\\w<>\\[\\]]*\\s+" + Pattern.quote(recv) + "\\s*=")
                            .matcher(m.text).find())
                    {
                        continue;
                    }
                    sites.add(gr.start());
                }
                if (isKeyClass)
                {
                    Matcher ae = ASN1_ENCODE_CALL.matcher(body);
                    while (ae.find())
                    {
                        if (ae.start() >= m.bodyStart && ae.start() < m.bodyEnd)
                        {
                            sites.add(ae.start());
                        }
                    }
                }

                for (int pos : sites)
                {
                    if (!(methodGuarded || inAnyRange(syncRanges, pos)))
                    {
                        int line = 1 + (int) body.substring(0, pos).chars().filter(c -> c == '\n').count();
                        violations.add(mainJava.relativize(source) + ":" + m.name + " (~line " + line + ")");
                    }
                }
            }
        }

        Assertions.assertTrue(violations.isEmpty(),
                "Non-private methods making a native call on a FIELD-held PKEYKeySpec (inline "
                        + "<field>.getReference() or via ASN1Encoder) WITHOUT keeping `this` reachable "
                        + "(synchronized(this) / reachabilityFence(this)) — the ML-KEM/ML-DSA/SLH-DSA key + "
                        + "KTS use-after-free class (see java-spi.md, \"Native references must outlive every "
                        + "JNI/FFI call\"): " + violations);
    }

    private static final class Method
    {
        final String modifiers;
        final String name;
        final int bodyStart;
        final int bodyEnd;
        final String text;

        Method(String modifiers, String name, int bodyStart, int bodyEnd, String text)
        {
            this.modifiers = modifiers;
            this.name = name;
            this.bodyStart = bodyStart;
            this.bodyEnd = bodyEnd;
            this.text = text;
        }
    }

    // Depth-based method extraction: a member body is a `{...}` opened while we
    // are directly inside the (first) type body, whose declaration ends in `)`
    // (optionally `throws ...`) — i.e. a method, not a field or nested type.
    private static List<Method> methods(String s)
    {
        List<Method> out = new ArrayList<Method>();
        int typeBrace = -1;
        java.util.regex.Matcher tm = Pattern.compile("\\b(class|interface|enum)\\b").matcher(s);
        if (tm.find())
        {
            typeBrace = s.indexOf('{', tm.end());
        }
        if (typeBrace < 0)
        {
            return out;
        }
        int depth = 0;
        int declStart = typeBrace + 1;
        for (int i = typeBrace + 1; i < s.length(); i++)
        {
            char c = s.charAt(i);
            if (c == '{')
            {
                if (depth == 0)
                {
                    String decl = s.substring(declStart, i);
                    int paren = decl.lastIndexOf(')');
                    // A method decl's last significant char before `{` is `)`
                    // (allowing a trailing `throws ...`); reject fields/blocks.
                    String tail = decl.substring(paren + 1).trim();
                    if (paren >= 0 && (tail.isEmpty() || tail.startsWith("throws")))
                    {
                        int bodyEnd = matchBrace(s, i);
                        java.util.regex.Matcher nm =
                                Pattern.compile("(\\w+)\\s*\\(").matcher(decl.substring(0, paren + 1));
                        String name = "";
                        while (nm.find())
                        {
                            name = nm.group(1);
                        }
                        String modifiers = decl.substring(0, Math.max(0, decl.indexOf(name)));
                        out.add(new Method(modifiers, name, i, bodyEnd, s.substring(i, Math.min(bodyEnd + 1, s.length()))));
                        i = bodyEnd;
                        declStart = bodyEnd + 1;
                        continue;
                    }
                }
                depth++;
            }
            else if (c == '}')
            {
                if (depth == 0)
                {
                    break; // end of type body
                }
                depth--;
                if (depth == 0)
                {
                    declStart = i + 1;
                }
            }
            else if (c == ';' && depth == 0)
            {
                declStart = i + 1;
            }
        }
        return out;
    }

    private static int matchBrace(String s, int open)
    {
        int depth = 0;
        for (int i = open; i < s.length(); i++)
        {
            if (s.charAt(i) == '{')
            {
                depth++;
            }
            else if (s.charAt(i) == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }
        }
        return s.length() - 1;
    }

    // Any synchronized(...) block, not just synchronized(this): a
    // `<holder>.getReference()` is kept reachable by holding the monitor of
    // whatever object owns the handle — synchronized(this) for the SPI's own
    // handle, synchronized(spec)/synchronized(key) for a key/spec handle (see
    // RSAComponents/DHComponents). The check only needs to catch the "no guard
    // at all" case (the ML-DSA engineUpdate UAF), so accepting any monitor
    // avoids false-positiving the legitimate spec-monitor pattern.
    private static final Pattern SYNCHRONIZED_OPEN = Pattern.compile("synchronized\\s*\\(");

    private static List<int[]> synchronizedThisRanges(String s)
    {
        List<int[]> ranges = new ArrayList<int[]>();
        java.util.regex.Matcher m = SYNCHRONIZED_OPEN.matcher(s);
        while (m.find())
        {
            int open = s.indexOf('{', m.end());
            if (open >= 0)
            {
                ranges.add(new int[]{m.start(), matchBrace(s, open)});
            }
        }
        return ranges;
    }

    private static boolean inAnyRange(List<int[]> ranges, int pos)
    {
        for (int[] r : ranges)
        {
            if (pos >= r[0] && pos <= r[1])
            {
                return true;
            }
        }
        return false;
    }

    // Remove block and line comments so getReference() in Javadoc/comments does
    // not register as a native call.
    private static String stripComments(String s)
    {
        String noBlock = s.replaceAll("(?s)/\\*.*?\\*/", "");
        return noBlock.replaceAll("//[^\\n]*", "");
    }

    private static String read(Path path)
        throws IOException
    {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    /**
     * Locate the {@code src/main/java} baseline source root relative to the test
     * working directory (the module dir under Gradle; a repo-root run is also
     * tolerated). Returns {@code null} when no source tree is reachable -- e.g.
     * the tests are being run from a packaged test jar -- so the caller can skip
     * rather than fail: a source-level lint has nothing to analyse there.
     */
    private static Path findMainJava()
    {
        String[] candidates = {"src/main/java", "jostle/src/main/java"};
        for (String candidate : candidates)
        {
            Path path = Paths.get(candidate);
            if (Files.isDirectory(path))
            {
                return path.toAbsolutePath().normalize();
            }
        }
        return null;
    }
}
