/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util;

import java.net.URI;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parser for a comma-separated {@code key=value} configuration string, with
 * per-value resolution schemes. This class is standalone and reusable: it has no
 * knowledge of any particular consumer's keys (e.g. the FIPS provider reads its
 * own {@code fips_*} keys from the returned map).
 *
 * <p><b>Grammar.</b> Pairs are separated by commas; each pair is {@code key=value}.
 * A value may be wrapped in matching double quotes, single quotes, or backticks,
 * in which case a comma inside the quotes is literal; an unquoted value runs to
 * the next comma. Whitespace around keys, the {@code =}, and unquoted values is
 * trimmed; whitespace inside quotes is preserved. Empty pairs (stray commas) are
 * ignored.
 *
 * <p><b>Value resolution.</b> Each value is resolved by its scheme prefix:
 * <ol>
 *   <li>{@code file://<uri>} — parsed as a file URI and resolved to a filesystem path.</li>
 *   <li>{@code prop:<name>} — a Jostle {@link Properties} property value (java.security
 *       {@code Security} property, then thread-local override, then a {@code -D} system
 *       property).</li>
 *   <li>{@code env:<NAME>} — an environment variable value.</li>
 *   <li>{@code str:<text>} — an explicit literal (escape hatch for text that would
 *       otherwise look like one of the schemes above).</li>
 *   <li>anything else — used verbatim as a literal string.</li>
 * </ol>
 *
 * <p><b>Result.</b> An unmodifiable {@link Map} in insertion order. Malformed input
 * (missing {@code =}, empty or duplicate key, unterminated quote, or trailing text
 * after a quoted value) throws {@link IllegalArgumentException}; a {@code prop:} or
 * {@code env:} reference that resolves to nothing also throws.
 */
public final class ConfigParser
{
    private static final String FILE_SCHEME = "file://";
    private static final String PROP_SCHEME = "prop:";
    private static final String ENV_SCHEME = "env:";
    private static final String STR_SCHEME = "str:";

    private ConfigParser()
    {
    }

    /**
     * Parse and resolve a {@code key=value} configuration string.
     *
     * @param config the configuration string (must not be null).
     * @return an unmodifiable map of key to resolved value, in insertion order.
     * @throws IllegalArgumentException if the string is malformed or a
     *                                  {@code prop:}/{@code env:} reference cannot be resolved.
     */
    public static Map<String, String> parse(String config)
    {
        if (config == null)
        {
            throw new IllegalArgumentException("config string is null");
        }

        Map<String, String> parsed = new LinkedHashMap<String, String>();
        int i = 0;
        int n = config.length();

        while (i < n)
        {
            // Skip separators (whitespace and stray/leading/trailing commas) between pairs.
            while (i < n && (Character.isWhitespace(config.charAt(i)) || config.charAt(i) == ','))
            {
                i++;
            }
            if (i >= n)
            {
                break;
            }

            // Key: up to the '='.
            int keyStart = i;
            while (i < n && config.charAt(i) != '=')
            {
                if (config.charAt(i) == ',')
                {
                    throw new IllegalArgumentException("config pair is missing '=': " + config);
                }
                i++;
            }
            if (i >= n)
            {
                throw new IllegalArgumentException("config pair is missing '=': " + config);
            }
            String key = config.substring(keyStart, i).trim();
            if (key.isEmpty())
            {
                throw new IllegalArgumentException("config has an empty key: " + config);
            }
            i++; // consume '='

            // Skip whitespace before the value.
            while (i < n && Character.isWhitespace(config.charAt(i)))
            {
                i++;
            }

            String rawValue;
            if (i < n && isQuote(config.charAt(i)))
            {
                char quote = config.charAt(i);
                i++; // consume opening quote
                int valueStart = i;
                while (i < n && config.charAt(i) != quote)
                {
                    i++;
                }
                if (i >= n)
                {
                    throw new IllegalArgumentException(
                            "config value for '" + key + "' has an unterminated quote");
                }
                rawValue = config.substring(valueStart, i);
                i++; // consume closing quote

                // Only whitespace, then a comma (or end of string), may follow a quoted value.
                while (i < n && Character.isWhitespace(config.charAt(i)))
                {
                    i++;
                }
                if (i < n && config.charAt(i) != ',')
                {
                    throw new IllegalArgumentException(
                            "config value for '" + key + "' has unexpected text after the quoted value");
                }
            }
            else
            {
                int valueStart = i;
                while (i < n && config.charAt(i) != ',')
                {
                    i++;
                }
                rawValue = config.substring(valueStart, i).trim();
            }

            if (parsed.containsKey(key))
            {
                throw new IllegalArgumentException("duplicate config key: " + key);
            }
            parsed.put(key, resolve(key, rawValue));
        }

        return Collections.unmodifiableMap(parsed);
    }

    private static boolean isQuote(char c)
    {
        return c == '"' || c == '\'' || c == '`';
    }

    private static String resolve(String key, String rawValue)
    {
        if (rawValue.startsWith(FILE_SCHEME))
        {
            try
            {
                return Paths.get(URI.create(rawValue)).toString();
            }
            catch (RuntimeException e)
            {
                throw new IllegalArgumentException(
                        "config value for '" + key + "' is not a valid file URL: " + rawValue, e);
            }
        }
        if (rawValue.startsWith(PROP_SCHEME))
        {
            String name = rawValue.substring(PROP_SCHEME.length());
            String resolved = Properties.getPropertyValue(name);
            if (resolved == null)
            {
                throw new IllegalArgumentException(
                        "config value for '" + key + "' references property '" + name + "', which is not set");
            }
            return resolved;
        }
        if (rawValue.startsWith(ENV_SCHEME))
        {
            String name = rawValue.substring(ENV_SCHEME.length());
            String resolved = AccessWrapper.doAction(() -> System.getenv(name));
            if (resolved == null)
            {
                throw new IllegalArgumentException(
                        "config value for '" + key + "' references environment variable '" + name
                                + "', which is not set");
            }
            return resolved;
        }
        if (rawValue.startsWith(STR_SCHEME))
        {
            return rawValue.substring(STR_SCHEME.length());
        }
        return rawValue;
    }
}
