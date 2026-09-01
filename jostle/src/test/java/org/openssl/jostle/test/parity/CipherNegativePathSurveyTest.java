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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * MT-31: measures, for every Cipher negative path, the exception TYPE we raise
 * against the type BouncyCastle raises for the identical input.
 *
 * <h2>This is an INSTRUMENT, not a guard</h2>
 *
 * <p>It asserts only that it MEASURED something - per-surface non-vacuity - and
 * deliberately does NOT assert that divergences are absent. Divergences are
 * pending per-family rulings from Megan, and a gate here would force premature
 * fixes and make the survey useless as a way of finding the next one. When a
 * ruling lands, that ruling becomes its own pinned test; this class stays as the
 * thing that finds what the pins do not yet cover.
 *
 * <h2>Every cell needs a POSITIVE baseline first</h2>
 *
 * <p>You cannot measure what type a corrupt ciphertext raises without a valid
 * ciphertext. So each cell first runs the same positive operation on both
 * providers with identical key, IV and input, and both must succeed and agree.
 * A cell whose baseline fails is reported {@code NO_BASELINE} - never silently
 * as agreement, which is how a survey comes to measure nothing and report
 * everything clean.
 *
 * <h2>Both-accepted is compared BYTE-WISE</h2>
 *
 * <p>An exception-level survey treats "neither threw" as agreement. MT-3's
 * key-wrap defect was exactly both-accept-different-output: no exception either
 * side, different bytes, and it round-tripped through our own unwrap. See
 * {@link ParityVerdict#SILENT_DIVERGENCE}.
 */
public class CipherNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

    /** Faults applied to every applicable cell. */
    enum Fault
    {
        SHORT_KEY,
        NULL_KEY,
        SHORT_IV,
        LONG_IV,
        FOREIGN_PARAM_SPEC,
        BAD_AEAD_TAG_LEN,
        UNINITIALISED_UPDATE,
        UNINITIALISED_DOFINAL,
        EMPTY_INPUT_DOFINAL,
        NON_ALIGNED_DOFINAL,
        NON_ALIGNED_UPDATE,
        SHORT_OUTPUT_DOFINAL,
        SHORT_OUTPUT_UPDATE,
        CORRUPT_CIPHERTEXT,
        TRUNCATED_CIPHERTEXT,
        /**
         * updateAAD on a mode that has no AAD. Added after a STATIC
         * enumeration of which JO_ codes each ni_ entry point can return
         * predicted a bare-RuntimeException site the behavioural catalogue
         * had missed entirely - see the class note on the two instruments.
         */
        AAD_ON_NON_AEAD
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

    /**
     * The transformation table. AES-family modes are taken from the MT-3
     * PIN/CLOSE table's reachable rows; CFB64, STREAM and POLY1305 are
     * deliberately absent because no caller can drive them (they resolve through
     * engineSetMode and then fail init), so they have no negative path to survey.
     */
    static List<CipherCell> cells()
    {
        List<CipherCell> c = new ArrayList<CipherCell>();
        //                        transformation             keyAlg    key iv aead tag wrap pad blk
        c.add(new CipherCell("AES/ECB/PKCS5Padding", "AES", 16, 0, false, 0, false, true, 16));
        c.add(new CipherCell("AES/ECB/NoPadding", "AES", 16, 0, false, 0, false, false, 16));
        c.add(new CipherCell("AES/CBC/PKCS5Padding", "AES", 16, 16, false, 0, false, true, 16));
        c.add(new CipherCell("AES/CBC/NoPadding", "AES", 16, 16, false, 0, false, false, 16));
        c.add(new CipherCell("AES/CBC/PKCS5Padding", "AES", 32, 16, false, 0, false, true, 16));
        c.add(new CipherCell("AES/CFB8/NoPadding", "AES", 16, 16, false, 0, false, false, 1));
        c.add(new CipherCell("AES/CFB/NoPadding", "AES", 16, 16, false, 0, false, false, 1));
        c.add(new CipherCell("AES/CTR/NoPadding", "AES", 16, 16, false, 0, false, false, 1));
        c.add(new CipherCell("AES/OFB/NoPadding", "AES", 16, 16, false, 0, false, false, 1));
        c.add(new CipherCell("AES/GCM/NoPadding", "AES", 16, 12, true, 128, false, false, 1));
        c.add(new CipherCell("AES/CCM/NoPadding", "AES", 16, 12, true, 64, false, false, 1));
        c.add(new CipherCell("AES/CTS/NoPadding", "AES", 16, 16, false, 0, false, false, 16));
        c.add(new CipherCell("AES/XTS/NoPadding", "AES", 32, 16, false, 0, false, false, 16));
        c.add(new CipherCell("AESWRAP", "AES", 32, 0, false, 0, true, false, 8));
        c.add(new CipherCell("AESWRAPPAD", "AES", 32, 0, false, 0, true, false, 8));
        c.add(new CipherCell("ARIA/CBC/PKCS5Padding", "ARIA", 16, 16, false, 0, false, true, 16));
        c.add(new CipherCell("CAMELLIA/CBC/PKCS5Padding", "CAMELLIA", 16, 16, false, 0, false, true, 16));
        c.add(new CipherCell("SM4/CBC/PKCS5Padding", "SM4", 16, 16, false, 0, false, true, 16));
        c.add(new CipherCell("DESede/CBC/PKCS5Padding", "DESede", 24, 8, false, 0, false, true, 8));
        c.add(new CipherCell("ChaCha20-Poly1305", "ChaCha20", 32, 12, true, 128, false, false, 1));
        return c;
    }

    // ------------------------------------------------------------------
    // measurement
    // ------------------------------------------------------------------

    private static Cipher c(Provider p, String xform) throws Exception
    {
        return Cipher.getInstance(xform, p);
    }

    private static AlgorithmParameterSpec spec(CipherCell cell, byte[] iv)
    {
        if (cell.ivBytes == 0)
        {
            return null;
        }
        return cell.aead ? new GCMParameterSpec(cell.tagBits, iv) : new IvParameterSpec(iv);
    }

    /** Positive operation, run identically on both providers. Null iv when the mode takes none. */
    private static Observation baseline(Provider p, CipherCell cell, byte[] key, byte[] iv, byte[] pt)
    {
        return Observer.observe(() -> {
            Cipher enc = c(p, cell.transformation);
            Key k = new SecretKeySpec(key, cell.keyAlgorithm);
            if (cell.wrap)
            {
                enc.init(Cipher.WRAP_MODE, k);
                return enc.wrap(new SecretKeySpec(pt, "AES"));
            }
            AlgorithmParameterSpec ps = spec(cell, iv);
            if (ps == null)
            {
                enc.init(Cipher.ENCRYPT_MODE, k);
            }
            else
            {
                enc.init(Cipher.ENCRYPT_MODE, k, ps);
            }
            return enc.doFinal(pt);
        });
    }

    private static Observation applyFault(Provider p, CipherCell cell, Fault f,
                                          byte[] key, byte[] iv, byte[] pt, byte[] validCt)
    {
        return Observer.observe(() -> {
            Key k = new SecretKeySpec(key, cell.keyAlgorithm);
            AlgorithmParameterSpec ps = spec(cell, iv);
            Cipher x;
            switch (f)
            {
                case SHORT_KEY:
                    x = c(p, cell.transformation);
                    initEnc(x, new SecretKeySpec(shorter(key), cell.keyAlgorithm), ps, cell);
                    return null;
                case NULL_KEY:
                    x = c(p, cell.transformation);
                    initEnc(x, null, ps, cell);
                    return null;
                case SHORT_IV:
                    x = c(p, cell.transformation);
                    initEnc(x, k, spec(cell, shorter(iv)), cell);
                    return null;
                case LONG_IV:
                    x = c(p, cell.transformation);
                    initEnc(x, k, spec(cell, longer(iv)), cell);
                    return null;
                case FOREIGN_PARAM_SPEC:
                    x = c(p, cell.transformation);
                    x.init(Cipher.ENCRYPT_MODE, k, new PBEParameterSpec(new byte[8], 1000));
                    return null;
                case BAD_AEAD_TAG_LEN:
                    x = c(p, cell.transformation);
                    x.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(24, iv));
                    return null;
                case UNINITIALISED_UPDATE:
                    return c(p, cell.transformation).update(pt);
                case UNINITIALISED_DOFINAL:
                    return c(p, cell.transformation).doFinal(pt);
                case EMPTY_INPUT_DOFINAL:
                    x = c(p, cell.transformation);
                    initEnc(x, k, ps, cell);
                    return x.doFinal(new byte[0]);
                case NON_ALIGNED_DOFINAL:
                    x = c(p, cell.transformation);
                    initEnc(x, k, ps, cell);
                    return x.doFinal(new byte[cell.blockBytes + 1]);
                case NON_ALIGNED_UPDATE:
                    x = c(p, cell.transformation);
                    initEnc(x, k, ps, cell);
                    return x.update(new byte[cell.blockBytes + 1]);
                case SHORT_OUTPUT_DOFINAL:
                {
                    x = c(p, cell.transformation);
                    initEnc(x, k, ps, cell);
                    byte[] out = new byte[Math.max(0, x.getOutputSize(pt.length) - 1)];
                    x.doFinal(pt, 0, pt.length, out, 0);
                    return out;
                }
                case SHORT_OUTPUT_UPDATE:
                {
                    x = c(p, cell.transformation);
                    initEnc(x, k, ps, cell);
                    byte[] out = new byte[Math.max(0, x.getOutputSize(pt.length) - 1)];
                    x.update(pt, 0, pt.length, out, 0);
                    // No bytes reported on the ACCEPT path. A single update's
                    // emission is not a cross-provider contract - BouncyCastle
                    // holds back a block on padded encrypt where EVP does not,
                    // so the two legitimately emit different amounts at the
                    // same point. Only the concatenation over a whole message
                    // is promised, and ChunkingContractTest already pins that.
                    // Returning the buffer here reported eight SILENT
                    // DIVERGENCEs that were untouched tail bytes, not output.
                    return null;
                }
                case CORRUPT_CIPHERTEXT:
                {
                    byte[] bad = validCt.clone();
                    // Never touch byte 0: for a modulus-bounded primitive that
                    // is the position that changes a padding failure into a
                    // structural one. Harmless here, uniform across surfaces.
                    bad[bad.length - 1] ^= (byte) 0x01;
                    return decrypt(p, cell, k, ps, bad);
                }
                case AAD_ON_NON_AEAD:
                    x = c(p, cell.transformation);
                    initEnc(x, k, ps, cell);
                    x.updateAAD(new byte[8]);
                    return null;
                case TRUNCATED_CIPHERTEXT:
                {
                    byte[] bad = new byte[validCt.length - 1];
                    System.arraycopy(validCt, 0, bad, 0, bad.length);
                    return decrypt(p, cell, k, ps, bad);
                }
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    private static byte[] decrypt(Provider p, CipherCell cell, Key k,
                                  AlgorithmParameterSpec ps, byte[] ct) throws Exception
    {
        Cipher dec = c(p, cell.transformation);
        if (cell.wrap)
        {
            dec.init(Cipher.UNWRAP_MODE, k);
            return dec.unwrap(ct, "AES", Cipher.SECRET_KEY).getEncoded();
        }
        if (ps == null)
        {
            dec.init(Cipher.DECRYPT_MODE, k);
        }
        else
        {
            dec.init(Cipher.DECRYPT_MODE, k, ps);
        }
        return dec.doFinal(ct);
    }

    private static void initEnc(Cipher x, Key k, AlgorithmParameterSpec ps, CipherCell cell) throws Exception
    {
        int mode = cell.wrap ? Cipher.WRAP_MODE : Cipher.ENCRYPT_MODE;
        if (ps == null)
        {
            x.init(mode, k);
        }
        else
        {
            x.init(mode, k, ps);
        }
    }

    private static byte[] shorter(byte[] b)
    {
        byte[] r = new byte[Math.max(0, b.length - 1)];
        System.arraycopy(b, 0, r, 0, r.length);
        return r;
    }

    private static byte[] longer(byte[] b)
    {
        byte[] r = new byte[b.length + 1];
        System.arraycopy(b, 0, r, 0, b.length);
        return r;
    }

    /** Which faults make sense for a given cell. */
    static boolean applicable(CipherCell cell, Fault f)
    {
        switch (f)
        {
            case SHORT_IV:
            case LONG_IV:
                return cell.ivBytes > 1;
            case BAD_AEAD_TAG_LEN:
                return cell.aead;
            case NON_ALIGNED_DOFINAL:
            case NON_ALIGNED_UPDATE:
                return cell.requiresAlignedInput();
            case AAD_ON_NON_AEAD:
                return !cell.aead && !cell.wrap;
            case FOREIGN_PARAM_SPEC:
            case SHORT_OUTPUT_DOFINAL:
            case SHORT_OUTPUT_UPDATE:
            case EMPTY_INPUT_DOFINAL:
                return !cell.wrap;
            default:
                return true;
        }
    }

    // ------------------------------------------------------------------
    // the survey
    // ------------------------------------------------------------------

    @Test
    public void surveyCipherNegativePaths()
    {
        List<String> rows = new ArrayList<String>();
        Map<ParityVerdict, Integer> tally = new EnumMap<ParityVerdict, Integer>(ParityVerdict.class);
        int measured = 0;
        int noBaseline = 0;

        for (CipherCell cell : cells())
        {
            byte[] key = new byte[cell.keyBytes];
            SR.nextBytes(key);
            byte[] iv = new byte[Math.max(cell.ivBytes, 1)];
            SR.nextBytes(iv);
            byte[] pt = new byte[cell.wrap ? 32 : cell.plaintextBytes];
            SR.nextBytes(pt);

            Observation ourBase = baseline(jsl, cell, key, iv, pt);
            Observation bcBase = baseline(bc, cell, key, iv, pt);
            ParityResult base = ExceptionParity.classify(ourBase, bcBase);

            if (base.verdict() == ParityVerdict.BC_ABSENT)
            {
                rows.add(row(cell, "(baseline)", new ParityResult(
                        ParityVerdict.BC_ABSENT, ourBase.typeName(), bcBase.typeName(), "")));
                bump(tally, ParityVerdict.BC_ABSENT);
                continue;
            }
            if (base.verdict() != ParityVerdict.MATCH_ACCEPT)
            {
                // Baseline did not agree - either a side refused a valid input,
                // or both accepted and produced different bytes. Report and do
                // NOT go on to apply faults: a fault applied on top of a broken
                // baseline measures nothing about the fault.
                rows.add(row(cell, "(baseline)", base));
                bump(tally, base.verdict());
                noBaseline++;
                continue;
            }

            byte[] validCt = ourBase.output();

            for (Fault f : Fault.values())
            {
                if (!applicable(cell, f))
                {
                    continue;
                }
                ParityResult r = ExceptionParity.classify(
                        applyFault(jsl, cell, f, key, iv, pt, validCt),
                        applyFault(bc, cell, f, key, iv, pt, validCt));
                rows.add(row(cell, f.name(), r));
                bump(tally, r.verdict());
                measured++;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("\n=== MT-31 Cipher negative-path survey ===\n");
        for (String r : rows)
        {
            sb.append(r).append('\n');
        }
        sb.append("--- tally ---\n");
        for (Map.Entry<ParityVerdict, Integer> e : tally.entrySet())
        {
            sb.append(String.format("  %-20s %d%n", e.getKey(), e.getValue()));
        }
        System.out.println(sb);

        // NON-VACUITY ONLY. Not a gate on divergences - see the class note.
        Assertions.assertTrue(measured >= 100,
                "survey measured only " + measured + " fault cells; it is not measuring the surface");
        Assertions.assertTrue(noBaseline * 4 < cells().size(),
                noBaseline + " of " + cells().size() + " cells had no working baseline;"
                        + " the survey is mostly not measuring anything");
    }

    private static void bump(Map<ParityVerdict, Integer> m, ParityVerdict v)
    {
        Integer n = m.get(v);
        m.put(v, n == null ? 1 : n + 1);
    }

    private static String row(CipherCell cell, String fault, ParityResult r)
    {
        String head = String.format("%-28s %-24s %-22s ours=%-40s bc=%-40s %s",
                cell.transformation + "/" + (cell.keyBytes * 8), fault, r.verdict(),
                simple(r.ourType()), simple(r.bcType()), r.qualifier());
        if (!r.isDivergence())
        {
            return head;
        }
        // Messages on divergences only. They are what tells a reader whether the
        // fault that was intended is the fault that landed - a short-key probe
        // reporting InvalidAlgorithmParameterException could be the provider
        // naming the key or the harness having disturbed something else, and
        // only the text separates those.
        return head + "\n" + String.format("%-28s %-24s   ours: %s%n%-28s %-24s     bc: %s",
                "", "", blank(r.ourMessage()), "", "", blank(r.bcMessage()));
    }

    private static String blank(String s)
    {
        return s == null || s.isEmpty() ? "(no message)" : s;
    }

    private static String simple(String fqcn)
    {
        int i = fqcn.lastIndexOf('.');
        return i < 0 ? fqcn : fqcn.substring(i + 1);
    }
}
