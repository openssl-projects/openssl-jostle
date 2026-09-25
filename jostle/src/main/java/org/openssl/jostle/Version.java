/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle;

import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Jostle version, read from the {@code version.properties} resource the build writes into the jar.
 * <p>
 * The string always starts with "v". When the resource is absent, has no {@code version} key, or holds a value
 * that does not parse, the version falls back to {@link #DEFAULT}; class initialisation never throws.
 */
public final class Version
{
    private static final Logger L = Logger.getLogger(Version.class.getName());

    static final String RESOURCE = "version.properties";
    static final String DEFAULT = "v0.1-SNAPSHOT";

    private static final String VERSION_STRING;
    private static final double VERSION_DOUBLE;
    private static final boolean FROM_RESOURCE;

    static
    {
        String value = null;
        double number = 0;
        try
        {
            value = normalise(readResource());
            number = toDouble(value);
        }
        catch (Exception e)
        {
            if (L.isLoggable(Level.FINE))
            {
                L.fine("version resource not used, falling back to " + DEFAULT + ": " + e.getMessage());
            }
            value = null;
        }

        if (value == null)
        {
            VERSION_STRING = DEFAULT;
            VERSION_DOUBLE = toDouble(DEFAULT);
            FROM_RESOURCE = false;
        }
        else
        {
            VERSION_STRING = value;
            VERSION_DOUBLE = number;
            FROM_RESOURCE = true;
        }
    }

    private Version()
    {
    }

    /**
     * Return the version string, always with a leading "v", for example "v1.2.3" or "v0.1-SNAPSHOT".
     */
    public static String getVersionString()
    {
        return VERSION_STRING;
    }

    /**
     * Return the version as a double suitable for a provider version: v1.2.3 is 1.0203.
     */
    public static double getVersionDouble()
    {
        return VERSION_DOUBLE;
    }

    /**
     * True when the version came from the resource, false when it is the fallback.
     */
    static boolean fromResource()
    {
        return FROM_RESOURCE;
    }

    private static String readResource()
            throws Exception
    {
        InputStream in = Version.class.getResourceAsStream(RESOURCE);
        if (in == null)
        {
            throw new IllegalStateException(RESOURCE + " not found");
        }
        Properties props = new Properties();
        try
        {
            props.load(in);
        }
        finally
        {
            in.close();
        }
        return props.getProperty("version");
    }

    /**
     * Trim the version and give it a leading "v".
     *
     * @throws IllegalArgumentException if the version is null or empty
     */
    static String normalise(String version)
    {
        if (version == null || version.trim().isEmpty())
        {
            throw new IllegalArgumentException("version is null or empty");
        }
        String v = version.trim();
        if (!v.startsWith("v"))
        {
            v = "v" + v;
        }
        return v;
    }

    /**
     * Convert a version to a double. A leading "v" and everything from the first "-" are dropped; the first
     * component is the integer part and each later component, padded with zeros to at least two digits, is
     * appended to the fraction: v1.2.3 is 1.0203 and 1.2.302 is 1.02302.
     *
     * @throws IllegalArgumentException if a component is not made of ASCII digits
     */
    static double toDouble(String version)
    {
        if (version == null)
        {
            throw new IllegalArgumentException("version is null");
        }
        String v = version.startsWith("v") ? version.substring(1) : version;
        int dash = v.indexOf('-');
        if (dash >= 0)
        {
            v = v.substring(0, dash);
        }

        String[] parts = v.split("\\.", -1);
        for (String part : parts)
        {
            if (!isDigits(part))
            {
                throw new IllegalArgumentException("version component '" + part + "' is not numeric in '"
                        + version + "'");
            }
        }

        StringBuilder fraction = new StringBuilder();
        for (int i = 1; i < parts.length; i++)
        {
            if (parts[i].length() < 2)
            {
                fraction.append('0');
            }
            fraction.append(parts[i]);
        }
        if (fraction.length() == 0)
        {
            fraction.append('0');
        }
        return Double.parseDouble(parts[0] + "." + fraction);
    }

    private static boolean isDigits(String s)
    {
        if (s.isEmpty())
        {
            return false;
        }
        for (int i = 0; i < s.length(); i++)
        {
            char c = s.charAt(i);
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        return true;
    }
}
