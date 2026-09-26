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

import org.junit.jupiter.api.Assertions;

import java.security.Provider;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The coverage rule behind {@code ExamplesCoverageTest} and {@code FIPSExamplesCoverageTest}: every primary,
 * non-OID service name a provider registers is exercised by at least one worked example of that provider's
 * part.
 * <p>
 * Exercised means an example method calls {@code <Type>.getInstance} with the name as a literal, or calls it
 * with a variable while the same method lists the name in a {@code String[]} initialiser or array literal
 * (the looping form used for long families). An alias credits its primary, and a Cipher transformation
 * credits the primary of that exact name or else its algorithm part, as JCA's lookup does.
 * <p>
 * A type still in the caller's pending list is not checked for coverage, and fails as soon as its own
 * examples class credits any of its names, so an entry cannot outlive its reason. Only that class counts
 * for this: a Cipher example that generates an RSA key pair credits KeyPairGenerator, which does not
 * un-pend it.
 */
public final class ExamplesCoverage
{
    private static final Pattern OID = Pattern.compile("\\d+(\\.\\d+)+");
    private static final Pattern DIRECT = Pattern.compile("\\b([A-Z]\\w*)\\.getInstance\\(\\s*\"([^\"]+)\"");
    private static final Pattern BY_VARIABLE = Pattern.compile(
            "\\b([A-Z]\\w*)\\.getInstance\\(\\s*[a-z]\\w*(?:\\[\\w+])?\\s*[,)]");
    private static final Pattern NAME_LIST = Pattern.compile(
            "(?:String\\[]\\s*\\w+\\s*=\\s*(?:new\\s+String\\[]\\s*)?|new\\s+String\\[]\\s*)\\{([^}]*)}",
            Pattern.DOTALL);
    private static final Pattern LITERAL = Pattern.compile("\"([^\"]+)\"");

    private ExamplesCoverage()
    {
    }

    public static void check(String part, Provider provider, Set<String> pending)
            throws Exception
    {
        check(part, provider, pending, ExamplesGuide.parseAll(ExamplesGuideCurrentTest.root()));
    }

    static void check(String part, Provider provider, Set<String> pending, List<ExamplesGuide.ExampleClass> classes)
    {
        Map<String, Set<String>> registered = new TreeMap<String, Set<String>>();
        for (Provider.Service s : provider.getServices())
        {
            if (OID.matcher(s.getAlgorithm()).matches())
            {
                continue;
            }
            // getServices() also lists SecureRandom.DEFAULT, which is an alias; count its primary.
            String primary = resolve(provider, s.getType(), s.getAlgorithm().toUpperCase(Locale.ROOT));
            Assertions.assertNotNull(primary, part + ": " + s.getType() + "." + s.getAlgorithm()
                    + " resolves to no registered primary");
            set(registered, s.getType()).add(primary);
        }
        Assertions.assertTrue(registered.size() >= 10,
                part + ": implausibly few service types registered: " + registered.keySet());

        Map<String, Set<String>> credited = new TreeMap<String, Set<String>>();
        Map<String, Set<String>> ownCredited = new TreeMap<String, Set<String>>();
        int methods = 0;
        for (ExamplesGuide.ExampleClass c : classes)
        {
            if (!c.part.equals(part))
            {
                continue;
            }
            for (ExamplesGuide.Method m : c.methods)
            {
                methods++;
                for (Map.Entry<String, Set<String>> e : credit(m.body, provider).entrySet())
                {
                    set(credited, e.getKey()).addAll(e.getValue());
                    if (e.getKey().equals(c.section()))
                    {
                        set(ownCredited, e.getKey()).addAll(e.getValue());
                    }
                }
            }
        }

        List<String> problems = new ArrayList<String>();
        for (String type : pending)
        {
            if (!registered.containsKey(type))
            {
                problems.add("pending type " + type + " is not registered at all");
            }
            if (ownCredited.containsKey(type))
            {
                problems.add("pending type " + type + " has examples in its own class " + ownCredited.get(type)
                        + "; remove it from the pending list");
            }
        }
        for (Map.Entry<String, Set<String>> e : registered.entrySet())
        {
            if (pending.contains(e.getKey()))
            {
                continue;
            }
            Set<String> missing = new TreeSet<String>(e.getValue());
            Set<String> got = credited.get(e.getKey());
            if (got != null)
            {
                missing.removeAll(got);
            }
            if (!missing.isEmpty())
            {
                problems.add(e.getKey() + " has no example for " + missing);
            }
        }
        Assertions.assertTrue(methods > 0 || pending.containsAll(registered.keySet()),
                part + ": no example methods were read");
        Assertions.assertTrue(problems.isEmpty(), part + ":\n  " + join(problems));
    }

    public static Map<String, Set<String>> credit(List<String> body, Provider provider)
    {
        StringBuilder sb = new StringBuilder();
        for (String line : body)
        {
            sb.append(line).append('\n');
        }
        String text = sb.toString();

        Map<String, Set<String>> out = new TreeMap<String, Set<String>>();
        Matcher direct = DIRECT.matcher(text);
        while (direct.find())
        {
            creditName(out, provider, direct.group(1), direct.group(2));
        }

        Set<String> loopedTypes = new HashSet<String>();
        Matcher byVariable = BY_VARIABLE.matcher(text);
        while (byVariable.find())
        {
            loopedTypes.add(byVariable.group(1));
        }
        Matcher list = NAME_LIST.matcher(text);
        while (list.find())
        {
            Matcher literal = LITERAL.matcher(list.group(1));
            while (literal.find())
            {
                for (String type : loopedTypes)
                {
                    creditName(out, provider, type, literal.group(1));
                }
            }
        }
        return out;
    }

    private static void creditName(Map<String, Set<String>> out, Provider provider, String type, String name)
    {
        String upper = name.toUpperCase(Locale.ROOT);
        String primary = resolve(provider, type, upper);
        if (primary == null && type.equals("Cipher") && upper.contains("/"))
        {
            primary = resolve(provider, type, upper.substring(0, upper.indexOf('/')));
        }
        if (primary != null)
        {
            set(out, type).add(primary);
        }
    }

    private static String resolve(Provider provider, String type, String upper)
    {
        String alias = provider.getProperty("Alg.Alias." + type + "." + upper);
        String primary = alias != null ? alias.toUpperCase(Locale.ROOT) : upper;
        return provider.getProperty(type + "." + primary) != null ? primary : null;
    }

    private static Set<String> set(Map<String, Set<String>> map, String key)
    {
        Set<String> s = map.get(key);
        if (s == null)
        {
            s = new TreeSet<String>();
            map.put(key, s);
        }
        return s;
    }

    private static String join(List<String> lines)
    {
        StringBuilder sb = new StringBuilder();
        for (String l : lines)
        {
            if (sb.length() > 0)
            {
                sb.append("\n  ");
            }
            sb.append(l);
        }
        return sb.toString();
    }
}
