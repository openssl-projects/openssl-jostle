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
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

/**
 * docs/jostle-ai-guide.md is exactly what {@link ExamplesGuide} generates from the example classes today. The
 * comparison is by line, so a CRLF checkout of either side compares equal, and a failure names the first line
 * that differs. The fix for a red run is {@code ./gradlew :jostle:generateExamplesGuide}, never a hand edit.
 */
public class ExamplesGuideCurrentTest
{
    static File root()
    {
        String root = System.getProperty("jostle.examples.root");
        Assertions.assertNotNull(root, "jostle.examples.root is not set by the build");
        File f = new File(root);
        Assertions.assertTrue(new File(f, ExamplesGuide.EXAMPLES).isDirectory(),
                "no examples under " + f);
        return f;
    }

    @Test
    public void theGuideOnDiskIsTheGeneratedGuide()
            throws Exception
    {
        File root = root();
        List<String> expected = ExamplesGuide.renderLines(root);
        List<String> actual = ExamplesGuide.readLines(new File(root, ExamplesGuide.GUIDE));

        int n = Math.min(expected.size(), actual.size());
        for (int i = 0; i < n; i++)
        {
            if (!expected.get(i).equals(actual.get(i)))
            {
                Assertions.fail(ExamplesGuide.GUIDE + " is stale at line " + (i + 1) + ": expected <"
                        + expected.get(i) + "> but found <" + actual.get(i)
                        + ">; run ./gradlew :jostle:generateExamplesGuide");
            }
        }
        Assertions.assertEquals(expected.size(), actual.size(), ExamplesGuide.GUIDE
                + " differs in length from the generated guide; run ./gradlew :jostle:generateExamplesGuide");
    }

    @Test
    public void aCrlfCopyOfTheGuideReadsTheSame()
            throws Exception
    {
        File root = root();
        File guide = new File(root, ExamplesGuide.GUIDE);
        List<String> lf = ExamplesGuide.readLines(guide);
        File crlf = File.createTempFile("guide-crlf", ".md");
        try
        {
            StringBuilder sb = new StringBuilder();
            for (String line : lf)
            {
                sb.append(line).append("\r\n");
            }
            java.nio.file.Files.write(crlf.toPath(), sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Assertions.assertEquals(lf, ExamplesGuide.readLines(crlf));
            Assertions.assertTrue(lf.size() > 100, "the guide is implausibly short: " + lf.size() + " lines");
        }
        finally
        {
            Assertions.assertTrue(crlf.delete());
        }
    }
}
