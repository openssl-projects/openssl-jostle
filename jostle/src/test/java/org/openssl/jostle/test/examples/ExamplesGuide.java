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

package org.openssl.jostle.test.examples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Generates docs/jostle-ai-guide.md from the hand-written preamble and the worked example classes under
 * jostle/src/test/examples. The example classes are the source of truth: each test method's Javadoc becomes
 * the prose and its body the code block. {@code ExamplesGuideCurrentTest} runs {@link #render(File)} in memory
 * and compares it to the file on disk, so the guide cannot drift from the examples.
 * <p>
 * The parser is deliberately strict. An example class may hold only Javadoc'd {@code @Test} methods (and, in
 * the per-part base class, one {@code @BeforeAll} setup method); anything else, a field or a helper, is an
 * error, because every example must be readable on its own.
 * <p>
 * Usage: {@code ./gradlew :jostle:generateExamplesGuide}, or run {@link #main} with the repository root.
 */
public final class ExamplesGuide
{
    public static final String GUIDE = "docs/jostle-ai-guide.md";
    public static final String PREAMBLE = "docs/jostle-ai-guide-preamble.md";
    public static final String EXAMPLES = "jostle/src/test/examples/jostle/examples";

    static final String GENERATED_MARKER =
            "<!-- Generated from jostle/src/test/examples; edit those and run "
                    + "./gradlew :jostle:generateExamplesGuide -->";

    private static final String[][] PARTS = {
            {"jsl", "JslExamples", "Worked examples: JSL"},
            {"fips", "FipsExamples", "Worked examples: JSLFIPS"},
    };

    private static final String CLASS_SUFFIX = "ExamplesTest";

    /**
     * The order sections appear in, within each part: hashing and keyed hashing, key derivation and
     * randomness, symmetric encryption and its keys and parameters, then asymmetric keys, signatures and
     * agreement, and last key storage and certificates. A class whose section is not listed is an error.
     */
    private static final String[] SECTION_ORDER = {
            "MessageDigest", "Mac", "SecretKeyFactory", "SecureRandom",
            "Cipher", "KeyGenerator", "AlgorithmParameters", "AlgorithmParameterGenerator",
            "KeyPairGenerator", "KeyFactory", "Signature", "KeyAgreement",
            "KeyStore", "CertificateFactory", "CertPathBuilder", "CertPathValidator",
    };

    private ExamplesGuide()
    {
    }

    /**
     * One rendered method: a {@code @Test} example or the base class's {@code @BeforeAll} setup.
     */
    public static final class Method
    {
        public final String name;
        public final boolean setup;
        public final List<String> javadoc;
        public final List<String> body;

        Method(String name, boolean setup, List<String> javadoc, List<String> body)
        {
            this.name = name;
            this.setup = setup;
            this.javadoc = Collections.unmodifiableList(javadoc);
            this.body = Collections.unmodifiableList(body);
        }
    }

    /**
     * One parsed example class.
     */
    public static final class ExampleClass
    {
        public final String part;
        public final String simpleName;
        public final List<String> javadoc;
        public final List<String> imports;
        public final List<Method> methods;

        ExampleClass(String part, String simpleName, List<String> javadoc, List<String> imports,
                     List<Method> methods)
        {
            this.part = part;
            this.simpleName = simpleName;
            this.javadoc = Collections.unmodifiableList(javadoc);
            this.imports = Collections.unmodifiableList(imports);
            this.methods = Collections.unmodifiableList(methods);
        }

        /**
         * The section heading: the class name without the Fips prefix and the ExamplesTest suffix.
         */
        public String section()
        {
            String s = simpleName.substring(0, simpleName.length() - CLASS_SUFFIX.length());
            if (part.equals("fips") && s.startsWith("Fips"))
            {
                s = s.substring("Fips".length());
            }
            return s;
        }
    }

    /**
     * Reads a text file as UTF-8 and splits it on either line ending, so a CRLF checkout reads the same lines.
     */
    public static List<String> readLines(File f)
            throws IOException
    {
        String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        List<String> lines = new ArrayList<String>(Arrays.asList(text.split("\r?\n", -1)));
        if (!lines.isEmpty() && lines.get(lines.size() - 1).isEmpty())
        {
            lines.remove(lines.size() - 1);
        }
        return lines;
    }

    /**
     * Every example class, base class first within each part, the rest in {@link #SECTION_ORDER}.
     */
    public static List<ExampleClass> parseAll(File root)
            throws IOException
    {
        List<ExampleClass> all = new ArrayList<ExampleClass>();
        for (String[] part : PARTS)
        {
            File dir = new File(root, EXAMPLES + "/" + part[0]);
            File base = new File(dir, part[1] + ".java");
            if (!base.isFile())
            {
                continue;
            }
            all.add(parse(part[0], base, true));
            String[] names = dir.list();
            if (names == null)
            {
                throw new IOException("cannot list " + dir);
            }
            ExampleClass[] ordered = new ExampleClass[SECTION_ORDER.length];
            for (String name : names)
            {
                if (name.endsWith(CLASS_SUFFIX + ".java"))
                {
                    ExampleClass c = parse(part[0], new File(dir, name), false);
                    int at = Arrays.asList(SECTION_ORDER).indexOf(c.section());
                    if (at < 0)
                    {
                        throw new IllegalStateException(part[0] + "/" + name + ": section " + c.section()
                                + " is not in ExamplesGuide.SECTION_ORDER");
                    }
                    if (ordered[at] != null)
                    {
                        throw new IllegalStateException(part[0] + "/" + name + ": a second class for section "
                                + c.section());
                    }
                    ordered[at] = c;
                }
                else if (!name.equals(base.getName()))
                {
                    throw new IllegalStateException(dir + "/" + name + ": only " + base.getName()
                            + " and *" + CLASS_SUFFIX + ".java belong in an examples package");
                }
            }
            for (ExampleClass c : ordered)
            {
                if (c != null)
                {
                    all.add(c);
                }
            }
        }
        if (all.isEmpty())
        {
            throw new IllegalStateException("no example classes under " + new File(root, EXAMPLES));
        }
        return all;
    }

    static ExampleClass parse(String part, File file, boolean base)
            throws IOException
    {
        List<String> lines = readLines(file);
        String simpleName = file.getName().substring(0, file.getName().length() - ".java".length());
        String where = part + "/" + file.getName();

        List<String> imports = new ArrayList<String>();
        List<String> classDoc = null;
        List<String> pendingDoc = null;
        List<String> pendingAnnotations = new ArrayList<String>();
        List<Method> methods = new ArrayList<Method>();
        boolean inClass = false;

        int i = 0;
        while (i < lines.size())
        {
            String line = lines.get(i);
            String trimmed = line.trim();
            int lineNo = i + 1;

            if (!inClass)
            {
                if (line.startsWith("import "))
                {
                    if (!line.startsWith("import org.junit."))
                    {
                        imports.add(line);
                    }
                    i++;
                }
                else if (line.startsWith("/**"))
                {
                    List<String> doc = new ArrayList<String>();
                    i = readJavadoc(lines, i, "", doc, where);
                    pendingDoc = doc;
                }
                else if (line.startsWith("public ") && line.contains(" class " + simpleName))
                {
                    if (pendingDoc == null)
                    {
                        throw new IllegalStateException(where + ":" + lineNo + ": class has no Javadoc");
                    }
                    classDoc = pendingDoc;
                    pendingDoc = null;
                    inClass = true;
                    i++;
                    if (!lines.get(i).equals("{"))
                    {
                        while (i < lines.size() && !lines.get(i).equals("{"))
                        {
                            i++;
                        }
                    }
                    i++;
                }
                else
                {
                    i++;
                }
                continue;
            }

            if (line.equals("}"))
            {
                inClass = false;
                i++;
                continue;
            }
            if (trimmed.isEmpty())
            {
                i++;
                continue;
            }
            if (line.startsWith("    /**"))
            {
                List<String> doc = new ArrayList<String>();
                i = readJavadoc(lines, i, "    ", doc, where);
                pendingDoc = doc;
                continue;
            }
            if (line.startsWith("    @"))
            {
                pendingAnnotations.add(trimmed);
                i++;
                continue;
            }
            if (line.startsWith("    public ") && line.contains("("))
            {
                String name = line.substring(0, line.indexOf('(')).trim();
                name = name.substring(name.lastIndexOf(' ') + 1);
                boolean isTest = pendingAnnotations.contains("@Test");
                boolean isSetup = pendingAnnotations.contains("@BeforeAll");
                if (!isTest && !isSetup)
                {
                    throw new IllegalStateException(where + ":" + lineNo + ": " + name
                            + " is neither @Test nor @BeforeAll; example classes hold no helpers");
                }
                if (isTest && base)
                {
                    throw new IllegalStateException(where + ":" + lineNo + ": the base class holds no examples");
                }
                if (isSetup && !base)
                {
                    throw new IllegalStateException(where + ":" + lineNo + ": setup belongs in the base class");
                }
                if (pendingDoc == null)
                {
                    throw new IllegalStateException(where + ":" + lineNo + ": " + name + " has no Javadoc");
                }
                while (i < lines.size() && !lines.get(i).equals("    {"))
                {
                    i++;
                }
                if (i == lines.size())
                {
                    throw new IllegalStateException(where + ":" + lineNo + ": no opening brace for " + name);
                }
                i++;
                List<String> body = new ArrayList<String>();
                while (i < lines.size() && !lines.get(i).equals("    }"))
                {
                    String b = lines.get(i);
                    if (b.trim().isEmpty())
                    {
                        body.add("");
                    }
                    else if (b.startsWith("        "))
                    {
                        body.add(b.substring(8));
                    }
                    else
                    {
                        throw new IllegalStateException(where + ":" + (i + 1) + ": body line of " + name
                                + " is not indented by eight spaces");
                    }
                    i++;
                }
                if (i == lines.size())
                {
                    throw new IllegalStateException(where + ":" + lineNo + ": no closing brace for " + name);
                }
                i++;
                methods.add(new Method(name, isSetup, pendingDoc, body));
                pendingDoc = null;
                pendingAnnotations.clear();
                continue;
            }
            throw new IllegalStateException(where + ":" + lineNo
                    + ": only Javadoc'd methods belong in an example class, found: " + trimmed);
        }

        if (classDoc == null)
        {
            throw new IllegalStateException(where + ": no public class " + simpleName);
        }
        if (base && (methods.size() != 1 || !methods.get(0).setup))
        {
            throw new IllegalStateException(where + ": the base class holds exactly one @BeforeAll method");
        }
        if (!base && methods.isEmpty())
        {
            throw new IllegalStateException(where + ": no examples");
        }
        return new ExampleClass(part, simpleName, classDoc, imports, methods);
    }

    /**
     * Reads a Javadoc block starting at {@code start}, appending its text as Markdown, and returns the index
     * of the line after the block.
     */
    private static int readJavadoc(List<String> lines, int start, String indent, List<String> out, String where)
    {
        if (!lines.get(start).equals(indent + "/**"))
        {
            throw new IllegalStateException(where + ":" + (start + 1) + ": Javadoc must open on a line of its own");
        }
        int i = start + 1;
        while (i < lines.size())
        {
            String line = lines.get(i);
            if (line.equals(indent + " */"))
            {
                while (!out.isEmpty() && out.get(out.size() - 1).isEmpty())
                {
                    out.remove(out.size() - 1);
                }
                return i + 1;
            }
            String text;
            if (line.equals(indent + " *"))
            {
                text = "";
            }
            else if (line.startsWith(indent + " * "))
            {
                text = line.substring(indent.length() + 3);
            }
            else
            {
                throw new IllegalStateException(where + ":" + (i + 1) + ": malformed Javadoc line");
            }
            if (text.equals("<p>"))
            {
                text = "";
            }
            text = text.replaceAll("\\{@code ([^}]*)}", "`$1`");
            if (text.contains("{@") || text.contains("<p>"))
            {
                throw new IllegalStateException(where + ":" + (i + 1)
                        + ": only {@code} and a <p> on its own line are supported in example Javadoc");
            }
            out.add(text);
            i++;
        }
        throw new IllegalStateException(where + ":" + (start + 1) + ": unterminated Javadoc");
    }

    /**
     * The whole guide, preamble included, as the list of its lines.
     */
    public static List<String> renderLines(File root)
            throws IOException
    {
        List<String> out = new ArrayList<String>(readLines(new File(root, PREAMBLE)));
        while (!out.isEmpty() && out.get(out.size() - 1).trim().isEmpty())
        {
            out.remove(out.size() - 1);
        }
        out.add("");
        out.add(GENERATED_MARKER);

        for (ExampleClass c : parseAll(root))
        {
            if (c.methods.get(0).setup)
            {
                String title = null;
                for (String[] part : PARTS)
                {
                    if (part[0].equals(c.part))
                    {
                        title = part[2];
                    }
                }
                out.add("");
                out.add("# " + title);
                out.add("");
                out.addAll(c.javadoc);
                out.add("");
                code(out, c.imports, c.methods.get(0).body);
                continue;
            }
            out.add("");
            out.add("## " + c.section());
            out.add("");
            out.addAll(c.javadoc);
            if (!c.imports.isEmpty())
            {
                out.add("");
                out.add("Imports used in this section:");
                out.add("");
                code(out, c.imports, Collections.<String>emptyList());
            }
            for (Method m : c.methods)
            {
                out.add("");
                out.add("### " + m.name);
                out.add("");
                out.addAll(m.javadoc);
                out.add("");
                code(out, Collections.<String>emptyList(), m.body);
            }
        }
        return out;
    }

    private static void code(List<String> out, List<String> imports, List<String> body)
    {
        out.add("```java");
        out.addAll(imports);
        if (!imports.isEmpty() && !body.isEmpty())
        {
            out.add("");
        }
        out.addAll(body);
        out.add("```");
    }

    /**
     * The whole guide as text, LF line endings, ending in one newline.
     */
    public static String render(File root)
            throws IOException
    {
        StringBuilder sb = new StringBuilder();
        for (String line : renderLines(root))
        {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    public static void main(String[] args)
            throws IOException
    {
        if (args.length != 1)
        {
            throw new IllegalArgumentException("usage: ExamplesGuide <repository root>");
        }
        File root = new File(args[0]);
        String text = render(root);
        File guide = new File(root, GUIDE);
        OutputStream out = new FileOutputStream(guide);
        try
        {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
        finally
        {
            out.close();
        }
        System.out.println("wrote " + GUIDE + ": " + renderLines(root).size() + " lines");
    }
}
