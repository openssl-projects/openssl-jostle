/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.ConfigParser;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ConfigParserTest
{
    // -----------------------------------------------------------------
    // basic parsing
    // -----------------------------------------------------------------

    @Test
    public void singleRawPair()
    {
        Map<String, String> map = ConfigParser.parse("a=b");
        Assertions.assertEquals(1, map.size());
        Assertions.assertEquals("b", map.get("a"));
    }

    @Test
    public void multiplePairsPreserveOrder()
    {
        Map<String, String> map = ConfigParser.parse("a=1, b=2, c=3");
        Assertions.assertEquals("1", map.get("a"));
        Assertions.assertEquals("2", map.get("b"));
        Assertions.assertEquals("3", map.get("c"));
        Assertions.assertEquals(new ArrayList<String>(java.util.Arrays.asList("a", "b", "c")),
                new ArrayList<String>(map.keySet()));
    }

    @Test
    public void emptyAndWhitespaceOnlyGiveEmptyMap()
    {
        Assertions.assertTrue(ConfigParser.parse("").isEmpty());
        Assertions.assertTrue(ConfigParser.parse("   ").isEmpty());
        Assertions.assertTrue(ConfigParser.parse(" , , ").isEmpty());
    }

    @Test
    public void whitespaceTrimmedAroundUnquotedButPreservedInQuotes()
    {
        Map<String, String> map = ConfigParser.parse("  a  =  b  ,  c = ' d '");
        Assertions.assertEquals("b", map.get("a"));
        Assertions.assertEquals(" d ", map.get("c"));
    }

    // -----------------------------------------------------------------
    // quoting
    // -----------------------------------------------------------------

    @Test
    public void allThreeQuoteStyles()
    {
        Assertions.assertEquals("v", ConfigParser.parse("k=\"v\"").get("k"));
        Assertions.assertEquals("v", ConfigParser.parse("k='v'").get("k"));
        Assertions.assertEquals("v", ConfigParser.parse("k=`v`").get("k"));
    }

    @Test
    public void commaInsideQuotesIsLiteral()
    {
        Map<String, String> map = ConfigParser.parse("a='x,y,z', b=2");
        Assertions.assertEquals("x,y,z", map.get("a"));
        Assertions.assertEquals("2", map.get("b"));
    }

    @Test
    public void equalsInsideQuotedValueIsLiteral()
    {
        Assertions.assertEquals("p=q=r", ConfigParser.parse("a='p=q=r'").get("a"));
    }

    @Test
    public void trailingAndDoubledCommasIgnored()
    {
        Map<String, String> map = ConfigParser.parse("a=b, , c=d,");
        Assertions.assertEquals(2, map.size());
        Assertions.assertEquals("b", map.get("a"));
        Assertions.assertEquals("d", map.get("c"));
    }

    // -----------------------------------------------------------------
    // value resolution schemes
    // -----------------------------------------------------------------

    @Test
    public void rawStringValue()
    {
        Assertions.assertEquals("just a string", ConfigParser.parse("k='just a string'").get("k"));
    }

    @Test
    public void fileUrlResolvesToPath()
    {
        // Round-trip a real path through file:// so the assertion is platform-agnostic.
        Path path = Paths.get(System.getProperty("java.io.tmpdir"), "providers", "fips.dylib");
        String url = path.toUri().toString();
        Assertions.assertEquals(path.toString(), ConfigParser.parse("module=" + url).get("module"));
    }

    @Test
    public void singleSlashFileUriResolvesToPath()
    {
        // java.io.File.toURI() produces the single-slash file:/path form -
        // it must resolve like the file:///path form, not fall through as a
        // raw literal.
        java.io.File file = new java.io.File(System.getProperty("java.io.tmpdir"), "fips.dylib");
        String url = file.toURI().toString();
        Assertions.assertTrue(url.startsWith("file:/"));
        Assertions.assertEquals(file.toPath().toString(),
                ConfigParser.parse("module=" + url).get("module"));
    }

    @Test
    public void malformedFileUrlThrows()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ConfigParser.parse("module=file://"));
    }

    @Test
    public void propSchemeResolvesViaProperties()
    {
        String name = "test.jostle.configparser.prop";
        System.setProperty(name, "resolved-from-property");
        try
        {
            // Both quoted and unquoted forms resolve the scheme identically.
            Assertions.assertEquals("resolved-from-property",
                    ConfigParser.parse("k=prop:" + name).get("k"));
            Assertions.assertEquals("resolved-from-property",
                    ConfigParser.parse("k=\"prop:" + name + "\"").get("k"));
        }
        finally
        {
            System.clearProperty(name);
        }
    }

    @Test
    public void propSchemeUnsetThrows()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ConfigParser.parse("k=prop:test.jostle.configparser.definitely.unset"));
    }

    @Test
    public void envSchemeResolvesViaEnvironment()
    {
        String path = System.getenv("PATH");
        Assumptions.assumeTrue(path != null && !path.isEmpty(),
                "PATH env var not set in this environment");
        Assertions.assertEquals(path, ConfigParser.parse("p=env:PATH").get("p"));
    }

    @Test
    public void envSchemeUnsetThrows()
    {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> ConfigParser.parse("p=env:JOSTLE_CONFIGPARSER_DEFINITELY_UNSET_VAR"));
    }

    @Test
    public void strSchemeForcesLiteralAndBypassesOtherSchemes()
    {
        // str: escapes text that would otherwise be treated as a prop:/env:/file:// reference.
        Assertions.assertEquals("prop:not-a-real-property",
                ConfigParser.parse("k='str:prop:not-a-real-property'").get("k"));
        Assertions.assertEquals("env:NOT_A_REAL_VAR",
                ConfigParser.parse("k=str:env:NOT_A_REAL_VAR").get("k"));
    }

    // -----------------------------------------------------------------
    // result is unmodifiable
    // -----------------------------------------------------------------

    @Test
    public void returnedMapIsUnmodifiable()
    {
        Map<String, String> map = ConfigParser.parse("a=b");
        Assertions.assertThrows(UnsupportedOperationException.class, () -> map.put("c", "d"));
    }

    // -----------------------------------------------------------------
    // malformed input
    // -----------------------------------------------------------------

    @Test
    public void nullConfigThrows()
    {
        Assertions.assertThrows(IllegalArgumentException.class, () -> ConfigParser.parse(null));
    }

    @Test
    public void malformedInputsThrow()
    {
        List<String> malformed = new ArrayList<String>();
        malformed.add("ab");            // no '='
        malformed.add("a");             // no '='
        malformed.add("=b");            // empty key
        malformed.add(" =b");           // empty key after trim
        malformed.add("a=b,a=c");       // duplicate key
        malformed.add("a=\"b");         // unterminated quote
        malformed.add("a=`b");          // unterminated backtick
        malformed.add("a=\"b\"c");      // trailing text after quoted value

        for (String bad : malformed)
        {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> ConfigParser.parse(bad), "expected rejection of: " + bad);
        }
    }
}
