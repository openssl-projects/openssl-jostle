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

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * The RFC 3211 family facts, in one place.
 *
 * <p>Keyed by the exact registered name. An unknown name fails rather than
 * defaulting: a prefix test with a fall-through would measure a new family
 * against AES's numbers and report success.
 *
 * <p>The block size is NOT a table fact — it is read from the SPI, so the two
 * cannot drift.
 */
public final class Rfc3211WrapFamilies
{
    /** Every RFC 3211 SPI sits under this package. */
    public static final String PREFIX = "org.openssl.jostle.jcajce.provider.wrap.";

    private static final Map<String, int[]> TABLE = buildTable();

    private static Map<String, int[]> buildTable()
    {
        Map<String, int[]> t = new LinkedHashMap<String, int[]>();
        t.put("AESRFC3211WRAP", new int[]{16, 24, 32});
        t.put("CAMELLIARFC3211WRAP", new int[]{16, 24, 32});
        t.put("DESEDERFC3211WRAP", new int[]{24});
        return t;
    }

    private Rfc3211WrapFamilies()
    {
    }

    /** The table's keys, for the guard that no row has gone stale. */
    public static Set<String> tableNames()
    {
        return TABLE.keySet();
    }

    /** The KEK lengths this name accepts. Unknown name, loud failure. */
    public static int[] kekLengthsOf(String name)
    {
        int[] row = TABLE.get(name.toUpperCase(Locale.ROOT));
        Assertions.assertNotNull(row, name + ": no KEK row. Add one rather than letting this"
                + " family be measured against another's lengths.");
        return row;
    }

    /** The shortest permitted KEK, for cells that just need a working one. */
    public static int anyValidKek(String name)
    {
        return kekLengthsOf(name)[0];
    }

    public static boolean isValidKek(String name, int len)
    {
        for (int ok : kekLengthsOf(name))
        {
            if (ok == len)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * The KEK lengths every family is probed at: each length ANY family
     * permits, plus one either side.
     *
     * <p>Fixed, not derived from the row under test. Deriving it would make
     * the table unfalsifiable — dropping a length would simply stop probing
     * it and stay green, so the sweep could quietly lose a length nobody
     * noticed had gone. Fixed, a dropped row asserts a refusal the provider
     * does not make.
     */
    private static final int[] KEK_SPREAD = {15, 16, 17, 23, 24, 25, 31, 32, 33};

    public static SortedSet<Integer> kekProbes(String name)
    {
        kekLengthsOf(name);   // the row must exist even though the spread is fixed
        SortedSet<Integer> out = new TreeSet<Integer>();
        for (int k : KEK_SPREAD)
        {
            out.add(k);
        }
        return out;
    }

    /** Asked of the SPI, never tabulated. */
    public static int blockOf(String name) throws Exception
    {
        int block = Cipher.getInstance(name, JostleProvider.PROVIDER_NAME).getBlockSize();
        Assertions.assertTrue(block > 0, name + ": the SPI reports no block size");
        return block;
    }

    /** The registered names, aliases included. */
    public static SortedSet<String> registeredNames()
    {
        SortedSet<String> out = new TreeSet<String>();
        for (String entry : ProviderSurfaceGuard.registeredSurface(
                java.security.Security.getProvider(JostleProvider.PROVIDER_NAME),
                PREFIX, new String[]{"Cipher"}))
        {
            out.add(entry.substring("Cipher.".length()));
        }
        Assertions.assertFalse(out.isEmpty(), "no RFC 3211 wrap is registered");
        return out;
    }
}
