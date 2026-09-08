/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * MT-68: a symmetric Cipher a caller can ask for should come with a way to make
 * a key for it.
 *
 * <p>ARIA, Camellia and SM4 were served as Ciphers with no {@code KeyGenerator},
 * so a caller had to build a {@code SecretKeySpec} by hand — using key bytes of
 * their own devising, from a source this provider knows nothing about. That is
 * the failure mode this guard exists to prevent recurring, and nothing else in
 * the suite could see it: every per-algorithm test supplies its own key.
 */
public class SymmetricKeyGeneratorCompletenessTest
{
    /**
     * Cipher names that legitimately have no {@code KeyGenerator}, each with the
     * reason. A name here is a CLAIM, so the vacuity guard below re-derives that
     * each is still registered — a stale entry cannot hide a real gap.
     */
    private static final Set<String> NO_KEY_GENERATOR;

    static
    {
        Set<String> s = new TreeSet<String>();
        // Asymmetric: keys come from a KeyPairGenerator, not a KeyGenerator.
        s.add("RSA");
        s.add("RSA-KTS-KEM-KWS");
        s.add("ML-KEM");
        // Uses a ChaCha20 key; KeyGenerator.ChaCha20 is the generator for it.
        s.add("CHACHA20-POLY1305");
        NO_KEY_GENERATOR = Collections.unmodifiableSet(s);
    }

    /** A run that considers fewer than this has a broken discovery, not a clean surface. */
    private static final int MIN_FAMILIES = 6;

    private static Provider jsl;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void everySymmetricCipherFamilyHasAKeyGenerator() throws Exception
    {
        Set<String> keyGenerators = new HashSet<String>();
        for (Provider.Service s : jsl.getServices())
        {
            if ("KeyGenerator".equals(s.getType()))
            {
                keyGenerators.add(s.getAlgorithm().toUpperCase());
            }
        }

        List<String> missing = new ArrayList<String>();
        int considered = 0;
        for (String family : bareCipherFamilies())
        {
            if (NO_KEY_GENERATOR.contains(family))
            {
                continue;
            }
            considered++;
            if (!keyGenerators.contains(family))
            {
                missing.add(family);
            }
        }

        Assertions.assertTrue(considered >= MIN_FAMILIES,
                "VACUOUS: only " + considered + " cipher families considered, expected at least "
                        + MIN_FAMILIES + " - discovery is broken, not the surface");

        Assertions.assertTrue(missing.isEmpty(),
                "these symmetric Ciphers are served with no KeyGenerator, so a caller must build a"
                        + " SecretKeySpec by hand: " + missing);
    }

    /** Every exclusion must still name a registered Cipher, or it is hiding a gap. */
    @Test
    public void theExcludedNamesAreStillRegisteredCiphers()
    {
        for (String excluded : NO_KEY_GENERATOR)
        {
            Assertions.assertNotNull(jsl.getService("Cipher", excluded),
                    excluded + " is excluded from the KeyGenerator requirement but is no longer a"
                            + " registered Cipher; delete the entry rather than leaving it to"
                            + " excuse a future gap");
        }
    }

    /** The generators must actually produce a usable key, not merely be registered. */
    @Test
    public void theNewGeneratorsProduceKeysOfTheRightSize() throws Exception
    {
        assertGenerates("ARIA", 256, new int[]{128, 192, 256});
        assertGenerates("CAMELLIA", 256, new int[]{128, 192, 256});
        assertGenerates("SM4", 128, new int[]{128});
    }

    private static void assertGenerates(String algorithm, int defaultBits, int[] sizes) throws Exception
    {
        SecretKey byDefault = KeyGenerator.getInstance(algorithm, jsl).generateKey();
        Assertions.assertEquals(defaultBits / 8, byDefault.getEncoded().length,
                algorithm + ": default key size");
        Assertions.assertEquals(algorithm, byDefault.getAlgorithm(), algorithm + ": key algorithm");

        for (int bits : sizes)
        {
            KeyGenerator kg = KeyGenerator.getInstance(algorithm, jsl);
            kg.init(bits);
            Assertions.assertEquals(bits / 8, kg.generateKey().getEncoded().length,
                    algorithm + ": init(" + bits + ")");
        }

        KeyGenerator bad = KeyGenerator.getInstance(algorithm, jsl);
        Assertions.assertThrows(java.security.InvalidParameterException.class, () -> bad.init(64),
                algorithm + ": an unsupported size must be refused with the JCA-named type");
    }

    /** Bare symmetric cipher names: no OID primaries, no explicit transformations. */
    private static Set<String> bareCipherFamilies()
    {
        Set<String> out = new TreeSet<String>();
        for (Provider.Service s : jsl.getServices())
        {
            if (!"Cipher".equals(s.getType()))
            {
                continue;
            }
            String name = s.getAlgorithm().toUpperCase();
            if (name.matches("[0-9.]+") || name.contains("/"))
            {
                continue;   // OID primary, or an explicit transformation
            }
            if (name.matches(".*(WRAP|KW|KWP|KWINV).*"))
            {
                continue;   // a wrap mode of a family counted under its bare name
            }
            out.add(name);
        }

        // Second pass, deliberately: dropping a sized variant DURING collection
        // depends on whether the bare name happened to be seen first, which
        // getServices() does not guarantee. The first version of this filter did
        // exactly that and reported CAMELLIA256 but not CAMELLIA128 — the
        // asymmetry is what gave it away.
        Set<String> sized = new TreeSet<String>();
        for (String name : out)
        {
            String bare = name.replaceAll("\\d+$", "");
            if (!bare.equals(name) && out.contains(bare))
            {
                sized.add(name);
            }
        }
        out.removeAll(sized);
        return out;
    }
}
