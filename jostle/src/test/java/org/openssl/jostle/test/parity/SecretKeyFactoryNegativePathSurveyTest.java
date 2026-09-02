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

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31 Group B, SecretKeyFactory: 42 names across 7 SPI classes.
 *
 * <h2>Most of this surface is UNCOMPARABLE BY CONSTRUCTION, not by absence</h2>
 *
 * <p>Six of the seven SPI classes take a Jostle-specific {@code KeySpec} -
 * {@code HKDFParameterSpec}, {@code KBKDFParameterSpec},
 * {@code SSHKDFParameterSpec}, {@code SSKDFParameterSpec},
 * {@code Argon2KeySpec}, {@code ScryptKeySpec}. Only PBKDF2 accepts a standard
 * one ({@code PBEKeySpec}).
 *
 * <p>So for those six there is no cross-provider comparison to make at the
 * valid-input level: BouncyCastle cannot be handed a
 * {@code org.openssl.jostle.jcajce.spec.HKDFParameterSpec}. This is a stronger
 * statement than "BouncyCastle does not serve the name" - even where it serves
 * one, the INPUT TYPE is ours. Recorded as UNCOMPARED, and deliberately not
 * counted as a coverage gap that better test-writing could close.
 *
 * <p>What IS comparable everywhere is the spec-agnostic surface: a null spec, a
 * foreign spec type, {@code getKeySpec} and {@code translateKey}. Those take
 * standard types on every provider, so they are surveyed three ways on all
 * seven families.
 *
 * <h2>The MT-46 recurrence probe</h2>
 *
 * <p>MT-46 found a generator floor with no matching import floor. The PBE
 * key-length faults are the same question on this surface: does a KDF bound the
 * key length a caller asks for, and does it agree with the references?
 */
public class SecretKeyFactoryNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;

    enum Fault
    {
        NULL_SPEC,
        FOREIGN_SPEC_TYPE,
        GET_KEY_SPEC_NULL_KEY,
        GET_KEY_SPEC_UNSUPPORTED_CLASS,
        TRANSLATE_NULL_KEY,
        TRANSLATE_FOREIGN_KEY,
        PBE_ZERO_ITERATIONS,
        PBE_NEGATIVE_ITERATIONS,
        PBE_ZERO_KEY_LENGTH,
        PBE_NEGATIVE_KEY_LENGTH,
        PBE_ABSURD_KEY_LENGTH,
        PBE_NULL_SALT,
        PBE_EMPTY_PASSWORD
    }

    static final class Cell
    {
        final String name;
        final String spiClass;
        /** True only where the family accepts the STANDARD PBEKeySpec. */
        final boolean takesPbeKeySpec;

        Cell(String name, String spiClass, boolean takesPbeKeySpec)
        {
            this.name = name;
            this.spiClass = spiClass;
            this.takesPbeKeySpec = takesPbeKeySpec;
        }
    }

    @BeforeAll
    public static void setUp()
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        bc = Security.getProvider("BC");
        if (bc == null)
        {
            bc = new BouncyCastleProvider();
            Security.addProvider(bc);
        }
    }

    static List<Cell> cells()
    {
        List<Cell> c = new ArrayList<Cell>();
        c.add(new Cell("PBKDF2WITHHMACSHA256", "PBKDF2SecretKeyFactory", true));
        c.add(new Cell("SCRYPT", "ScryptSecretKeyFactory", false));
        c.add(new Cell("ARGON2", "Argon2SecretKeyFactory", false));
        c.add(new Cell("HKDF-SHA256", "HKDFSecretKeyFactory", false));
        c.add(new Cell("KBKDF-HMAC-SHA256", "KBKDFSecretKeyFactory", false));
        c.add(new Cell("SSHKDF-SHA256", "SSHKDFSecretKeyFactory", false));
        c.add(new Cell("SSKDF-SHA256", "SSKDFSecretKeyFactory", false));
        return c;
    }

    private static Observation applyFault(Provider p, Cell cell, Fault f)
    {
        return Observer.observe(() -> {
            SecretKeyFactory kf = SecretKeyFactory.getInstance(cell.name, p);
            char[] pw = "correct horse battery staple".toCharArray();
            byte[] salt = new byte[16];
            switch (f)
            {
                case NULL_SPEC:
                    return kf.generateSecret(null).getEncoded();
                case FOREIGN_SPEC_TYPE:
                    // A DESKeySpec is a KeySpec no KDF factory serves.
                    return kf.generateSecret(new javax.crypto.spec.DESKeySpec(new byte[8])).getEncoded();
                case GET_KEY_SPEC_NULL_KEY:
                {
                    Object o = kf.getKeySpec(null, PBEKeySpec.class);
                    return o == null ? null : new byte[0];
                }
                case GET_KEY_SPEC_UNSUPPORTED_CLASS:
                {
                    Object o = kf.getKeySpec(new SecretKeySpec(new byte[16], "AES"),
                            javax.crypto.spec.DESKeySpec.class);
                    return o == null ? null : new byte[0];
                }
                case TRANSLATE_NULL_KEY:
                {
                    javax.crypto.SecretKey k = kf.translateKey(null);
                    return k == null ? null : k.getEncoded();
                }
                case TRANSLATE_FOREIGN_KEY:
                {
                    javax.crypto.SecretKey k = kf.translateKey(new SecretKeySpec(new byte[16], "AES"));
                    return k == null ? null : k.getEncoded();
                }
                // The PBEKeySpec constructor itself rejects some of these, so
                // it is built INSIDE the observed call - otherwise the throw
                // would escape the harness instead of being recorded as the
                // provider-visible behaviour for that input.
                case PBE_ZERO_ITERATIONS:
                    return kf.generateSecret(new PBEKeySpec(pw, salt, 0, 256)).getEncoded();
                case PBE_NEGATIVE_ITERATIONS:
                    return kf.generateSecret(new PBEKeySpec(pw, salt, -1, 256)).getEncoded();
                case PBE_ZERO_KEY_LENGTH:
                    return kf.generateSecret(new PBEKeySpec(pw, salt, 1000, 0)).getEncoded();
                case PBE_NEGATIVE_KEY_LENGTH:
                    return kf.generateSecret(new PBEKeySpec(pw, salt, 1000, -8)).getEncoded();
                case PBE_ABSURD_KEY_LENGTH:
                    // The MT-46 recurrence probe: is the requested key length
                    // bounded at all? Deliberately large but not so large that
                    // an unbounded provider allocates for minutes.
                    return kf.generateSecret(new PBEKeySpec(pw, salt, 1, 1 << 22)).getEncoded();
                case PBE_NULL_SALT:
                    return kf.generateSecret(new PBEKeySpec(pw, null, 1000, 256)).getEncoded();
                case PBE_EMPTY_PASSWORD:
                    return kf.generateSecret(new PBEKeySpec(new char[0], salt, 1000, 256)).getEncoded();
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    static boolean applicable(Cell cell, Fault f)
    {
        if (f.name().startsWith("PBE_"))
        {
            // A PBEKeySpec into a factory that does not take one measures
            // FOREIGN_SPEC_TYPE again under seven different names.
            return cell.takesPbeKeySpec;
        }
        return true;
    }

    @Test
    public void surveySecretKeyFactoryNegativePaths()
    {
        SurveyReport report = new SurveyReport("MT-31 SecretKeyFactory negative-path survey");
        List<Cell> cells = cells();

        for (Cell cell : cells)
        {
            Provider jdk = JdkComparator.forService("SecretKeyFactory", cell.name);
            report.note(String.format("%-26s %-32s spec=%s  bc=%s  jdk=%s", cell.name, "(comparability)",
                    cell.takesPbeKeySpec ? "STANDARD PBEKeySpec" : "Jostle-specific - valid input not shareable",
                    bc.getService("SecretKeyFactory", cell.name) == null ? "absent" : "present",
                    jdk == null ? "absent" : jdk.getName()));

            for (Fault f : Fault.values())
            {
                if (!applicable(cell, f))
                {
                    continue;
                }
                report.cell(cell.name, f.name(), ThreeWay.classify(
                        applyFault(jsl, cell, f),
                        bc.getService("SecretKeyFactory", cell.name) == null
                                ? Observation.absent() : applyFault(bc, cell, f),
                        jdk == null ? Observation.absent() : applyFault(jdk, cell, f)));
            }
        }
        // Absolute floor: seven cells times six spec-agnostic faults, plus the
        // seven PBE faults on the one family that takes a standard spec.
        report.assertMeasured(49, cells.size(), 0);
    }

    @Test
    public void everySecretKeyFactorySpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"SecretKeyFactory".equals(sv.getType()))
            {
                continue;
            }
            direct++;
            String cn = sv.getClassName();
            String simple = cn.substring(cn.lastIndexOf('.') + 1);
            List<String> l = byClass.get(simple);
            if (l == null)
            {
                l = new ArrayList<String>();
                byClass.put(simple, l);
            }
            l.add(sv.getAlgorithm());
        }
        Set<String> covered = new HashSet<String>();
        for (Cell c : cells())
        {
            covered.add(c.spiClass);
        }
        int named = 0;
        List<String> uncovered = new ArrayList<String>();
        StringBuilder sb = new StringBuilder("\n=== SecretKeyFactory SPI-class census ===\n");
        for (Map.Entry<String, List<String>> e : byClass.entrySet())
        {
            named += e.getValue().size();
            if (!covered.contains(e.getKey()))
            {
                uncovered.add(e.getKey());
            }
            sb.append(String.format("  %-30s %2d names  %s%n", e.getKey(), e.getValue().size(),
                    covered.contains(e.getKey()) ? "covered" : "NO CELL"));
        }
        sb.append(String.format("  %-30s %2d names across %d classes%n", "TOTAL", named, byClass.size()));
        System.out.println(sb);
        Assertions.assertTrue(byClass.size() >= 6,
                "census found only " + byClass.size() + " SecretKeyFactory SPI classes; not reading the provider");
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered SecretKeyFactory count " + direct);
        Assertions.assertTrue(uncovered.isEmpty(),
                "SecretKeyFactory SPI classes with no survey cell: " + uncovered);
        Set<String> unknown = new HashSet<String>(covered);
        unknown.removeAll(byClass.keySet());
        Assertions.assertTrue(unknown.isEmpty(),
                "survey cells name SPI classes the provider does not register: " + unknown);
    }
}
