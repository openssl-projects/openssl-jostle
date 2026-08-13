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

package org.openssl.jostle.test;

import org.junit.jupiter.api.Assertions;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Runs a probe class in a fresh JVM and parses the {@code PROBE key=value} lines it prints.
 * <p>
 * Exists because several of Jostle's system properties are consumed exactly once during class
 * initialisation - {@code Loader}'s properties behind its {@code loadAttempted} latch,
 * {@code CryptoServicesRegistrar.ENFORCE_PROVIDER_RANDOM} into a {@code static final} field.
 * By the time a test body runs those classes have long since initialised, so
 * {@code System.setProperty} is a no-op and the only way to exercise such a property is to
 * hand it to a JVM at start-up.
 * <p>
 * The child inherits this JVM's classpath and environment but none of its {@code -D} flags,
 * so properties the gradle test tasks set (notably
 * {@code org.openssl.jostle.loader.interface}) do not leak in and each probe states exactly
 * the configuration it wants. Inheriting the environment is deliberate: it is what lets a
 * child see {@code TEST_FIPS_LIB} and stand up the FIPS provider for itself.
 */
public final class JvmProbe
{
    /**
     * Marker prefix on every reported line. Lets the caller pick probe output out of a stream
     * that also carries JVM warnings (restricted native access, and so on).
     */
    public static final String PREFIX = "PROBE ";

    private static final long TIMEOUT_SECONDS = 120L;

    private JvmProbe()
    {
    }

    /**
     * Report one value from inside a probe's {@code main}.
     */
    public static void emit(String key, String value)
    {
        //
        // Flatten newlines: an exception message reaching the output must stay on one line or
        // the caller's line-oriented parse would drop the tail.
        //
        String flat = String.valueOf(value).replace('\r', ' ').replace('\n', ' ');
        System.out.println(PREFIX + key + "=" + flat);
    }

    /**
     * Convenience builder for the property map, taking alternating keys and values.
     */
    public static Map<String, String> props(String... keyThenValue)
    {
        if ((keyThenValue.length & 1) != 0)
        {
            throw new IllegalArgumentException("expected key/value pairs");
        }

        Map<String, String> out = new LinkedHashMap<>();
        for (int t = 0; t < keyThenValue.length; t += 2)
        {
            out.put(keyThenValue[t], keyThenValue[t + 1]);
        }
        return out;
    }

    /**
     * Launch {@code mainClass} in a fresh JVM with the given system properties and arguments,
     * and return everything it reported. Fails the calling test if the child times out or
     * exits non-zero.
     */
    public static Result run(Class<?> mainClass, Map<String, String> systemProperties, String... args)
            throws Exception
    {
        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        for (Map.Entry<String, String> entry : systemProperties.entrySet())
        {
            command.add("-D" + entry.getKey() + "=" + entry.getValue());
        }
        command.add(mainClass.getName());
        Collections.addAll(command, args);

        ProcessBuilder builder = new ProcessBuilder(command);
        //
        // Merge stderr in rather than draining two pipes: JVM warnings land on stderr and
        // would otherwise risk filling the pipe buffer while we read stdout. The PROBE prefix
        // separates our lines from theirs.
        //
        builder.redirectErrorStream(true);

        Process process = builder.start();

        List<String> output = new ArrayList<>();
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), Charset.forName("UTF-8")));
        try
        {
            String line = reader.readLine();
            while (line != null)
            {
                output.add(line);
                line = reader.readLine();
            }
        }
        finally
        {
            reader.close();
        }

        if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS))
        {
            process.destroyForcibly();
            Assertions.fail("probe JVM did not exit within " + TIMEOUT_SECONDS + "s");
        }

        Assertions.assertEquals(0, process.exitValue(),
                "probe JVM exited non-zero, output:\n" + join(output));

        return Result.parse(output);
    }

    private static String javaExecutable()
    {
        File bin = new File(new File(System.getProperty("java.home"), "bin"), "java");
        if (bin.isFile())
        {
            return bin.getAbsolutePath();
        }
        return new File(new File(System.getProperty("java.home"), "bin"), "java.exe").getAbsolutePath();
    }

    static String join(List<String> lines)
    {
        StringBuilder sb = new StringBuilder();
        for (String line : lines)
        {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    /**
     * The {@code PROBE key=value} lines a child JVM reported, parsed.
     */
    public static final class Result
    {
        private final Map<String, String> values;
        private final List<String> raw;

        private Result(Map<String, String> values, List<String> raw)
        {
            this.values = values;
            this.raw = raw;
        }

        static Result parse(List<String> output)
        {
            Map<String, String> values = new LinkedHashMap<>();
            for (String line : output)
            {
                if (!line.startsWith(PREFIX))
                {
                    continue;
                }

                String body = line.substring(PREFIX.length());
                int eq = body.indexOf('=');
                if (eq < 0)
                {
                    continue;
                }

                values.put(body.substring(0, eq), body.substring(eq + 1));
            }

            Assertions.assertFalse(values.isEmpty(),
                    "no probe output recovered, child said:\n" + join(output));
            return new Result(values, output);
        }

        public String get(String key)
        {
            Assertions.assertTrue(values.containsKey(key),
                    "probe did not report '" + key + "', child said:\n" + join(raw));
            return values.get(key);
        }

        public List<String> raw()
        {
            return Collections.unmodifiableList(raw);
        }
    }
}
