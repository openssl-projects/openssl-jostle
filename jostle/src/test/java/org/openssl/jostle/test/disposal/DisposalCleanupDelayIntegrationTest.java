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

package org.openssl.jostle.test.disposal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The delayed cleanup path.
 *
 * <p>{@code org.openssl.jostle.native.cleanup_delay} is read once in the
 * daemon's static initialiser, so the child runs in its own JVM. The
 * discriminator is the THREAD the disposal runs on: the daemon thread when the
 * delay is zero, the cleanup executor when it is not.
 */
public class DisposalCleanupDelayIntegrationTest
{
    private static final String DELAY_PROP = "org.openssl.jostle.native.cleanup_delay";

    private static String runChild(String... vmArgs) throws Exception
    {
        List<String> cmd = new ArrayList<String>();
        cmd.add(System.getProperty("java.home") + File.separator + "bin" + File.separator + "java");
        for (String a : vmArgs)
        {
            cmd.add(a);
        }
        cmd.add("-cp");
        cmd.add(System.getProperty("java.class.path"));
        cmd.add(DisposalCleanupDelayProbe.class.getName());

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        StringBuilder out = new StringBuilder();
        BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null)
        {
            out.append(line).append('\n');
        }
        r.close();

        Assertions.assertTrue(p.waitFor(120, TimeUnit.SECONDS), "the child JVM did not exit");
        Assertions.assertEquals(0, p.exitValue(), "child failed:\n" + out);
        return out.toString();
    }

    private static String disposedOn(String output)
    {
        for (String line : output.split("\n"))
        {
            if (line.startsWith(DisposalCleanupDelayProbe.PREFIX))
            {
                return line.substring(DisposalCleanupDelayProbe.PREFIX.length()).trim();
            }
        }
        throw new AssertionError("child printed no result line:\n" + output);
    }

    @Test
    public void aConfiguredDelayDisposesOnTheCleanupExecutor() throws Exception
    {
        String delayed = disposedOn(runChild("-D" + DELAY_PROP + "=50"));
        Assertions.assertNotEquals("null", delayed,
                "nothing was disposed in the child with a delay configured");
        Assertions.assertTrue(delayed.contains("Cleanup Executor"),
                "with a delay configured the disposal must run on the cleanup executor,"
                        + " but it ran on: " + delayed);
    }

    /**
     * The control. Without it the cell above passes on a build where every
     * disposal runs on the executor regardless of the property, which would mean
     * the property was doing nothing.
     */
    @Test
    public void noDelayDisposesOnTheDaemonThread() throws Exception
    {
        String immediate = disposedOn(runChild());
        Assertions.assertNotEquals("null", immediate,
                "nothing was disposed in the child with no delay configured");
        Assertions.assertFalse(immediate.contains("Cleanup Executor"),
                "with no delay the disposal must not run on the cleanup executor,"
                        + " but it ran on: " + immediate);
    }
}
