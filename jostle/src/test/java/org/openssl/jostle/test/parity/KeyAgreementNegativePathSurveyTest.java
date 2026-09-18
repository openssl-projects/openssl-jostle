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

import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31, KeyAgreement surface: our exception type against BouncyCastle's.
 *
 * <h2>The catalogue is PHASE-shaped and shares nothing with a digest's</h2>
 *
 * <p>KeyAgreement is the one Group A surface whose faults are not "bad bytes in,
 * what comes out" - it is a small state machine (init, doPhase, generateSecret)
 * and most of its negative paths are ORDERING faults rather than value faults.
 * The observation shapes are the same as the other two surfaces, which is why
 * this shares their machinery; the fault catalogue is entirely its own.
 *
 * <h2>The finish FORM is a dimension, driven separately from the fault</h2>
 *
 * <p>JCA offers three ways to finish an agreement - {@code generateSecret()},
 * {@code generateSecret(String)} and {@code generateSecret(byte[], int)} - and
 * they are different code paths. Every fault that reaches a finish is therefore
 * driven under each, and the row names which. A fault that fails at init or
 * doPhase reaches no finish and carries no form.
 *
 * <p>One knob must not choose the form for every fault of a cell: that leaves
 * the other two forms unreached with nothing saying so.
 *
 * <p>The KDF-bearing agreements deliberately SEAL {@code generateSecret()}: a
 * KDF agreement yields keys only through {@code generateSecret(String)}, the
 * raw forms refuse, pinned by {@code KeyAgreementKDFTest}. That is now a
 * measured row per form rather than a cell-shape assumption: a form whose
 * baseline does not agree contributes {@code NO_BASELINE} rows and never
 * disappears.
 *
 * <p>The baseline gate is per FORM, not per cell. A cell-wide gate would let a
 * refused form destroy the rows of a working one, and the derived row count
 * would then fail on a survey that is behaving correctly.
 *
 * <p>This was got wrong first: the shape probe tried {@code generateSecret()}
 * then {@code generateSecret("AES")}, and reported both KDF families as
 * outright failures on our side. "AES" is not a wrap algorithm the KDF can size
 * a key for, so the second attempt raised {@code NoSuchAlgorithmException} and
 * the cell looked broken. The sealing is deliberate and the wrap OID is the
 * documented way in - a harness fault, caught before it reached a report, and
 * the third of this arc.
 */
public class KeyAgreementNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();
    /** id-aes256-wrap: what the KDF variants size their derived key from. */
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";
    /** A valid RFC 6637 §8 Param, for the one cell whose init requires one. */
    private static final byte[] CKDF_UKM = {1, 2, 3, 4, 5, 6, 7, 8};

    /**
     * The three JCA finish overloads. {@code NONE} is not an overload: it
     * labels a fault that fails before any finish is reached, so its row has
     * no form.
     */
    enum Form
    {
        NONE,
        RAW,
        NAMED,
        BUFFER
    }

    /** Every form that reaches a finish, and so is driven for a baseline. */
    private static final EnumSet<Form> DRIVEABLE =
            EnumSet.of(Form.RAW, Form.NAMED, Form.BUFFER);

    /**
     * Capacity for the BUFFER form. The largest secret in the survey is a
     * 2048-bit DH value at 256 bytes, so this is four times the bound. It is a
     * capacity, not an expected size: a {@code ShortBufferException} here, or a
     * reported length above it, is a recorded outcome and not a harness fault.
     */
    private static final int BUFFER_CAPACITY = 1024;

    /**
     * The fault catalogue, each carrying the forms it is driven under.
     *
     * <p>A fault is form-dependent only when a finish actually executes and its
     * outcome is observed. Seven fail at init or doPhase and reach no finish;
     * one is inherently a buffer probe. Driving all thirteen under all three
     * forms would produce duplicates rather than coverage.
     */
    enum Fault
    {
        NULL_KEY_INIT(Form.NONE),
        WRONG_FAMILY_KEY_INIT(Form.NONE),
        PUBLIC_KEY_FOR_INIT(Form.NONE),
        FOREIGN_PARAM_SPEC_INIT(Form.NONE),
        DOPHASE_BEFORE_INIT(Form.NONE),
        GENERATE_SECRET_BEFORE_INIT(Form.RAW, Form.NAMED, Form.BUFFER),
        GENERATE_SECRET_BEFORE_DOPHASE(Form.RAW, Form.NAMED, Form.BUFFER),
        NULL_PUBLIC_KEY_DOPHASE(Form.NONE),
        WRONG_FAMILY_PUBLIC_KEY_DOPHASE(Form.NONE),
        OWN_PUBLIC_KEY_DOPHASE(Form.RAW, Form.NAMED, Form.BUFFER),
        DOPHASE_NOT_LAST_THEN_GENERATE(Form.RAW, Form.NAMED, Form.BUFFER),
        GENERATE_SECRET_TWICE(Form.RAW, Form.NAMED, Form.BUFFER),
        SHORT_OUTPUT_GENERATE_SECRET(Form.BUFFER);

        private final EnumSet<Form> forms;

        Fault(Form first, Form... rest)
        {
            this.forms = EnumSet.of(first, rest);
        }

        EnumSet<Form> forms()
        {
            return forms;
        }
    }

    /**
     * Rows a fully-measured cell must produce, DERIVED from the catalogue: one
     * baseline per driveable form, plus each fault once per applicable form. A
     * typed literal goes stale the moment a fault or a form is added, which is
     * the defect class this dimension exists to remove.
     */
    private static int rowsPerCell()
    {
        int n = DRIVEABLE.size();
        for (Fault f : Fault.values())
        {
            n += f.forms().size();
        }
        return n;
    }

    /** One agreement under survey. */
    static final class Cell
    {
        final String name;
        final String spiClass;
        final String kpgAlgorithm;
        final String bcKeyFactory;
        /**
         * Algorithm the NAMED form asks generateSecret for. ONE constant
         * across every cell, so a NAMED divergence is attributable to the
         * family rather than to the algorithm chosen for that row.
         */
        final String secretAlgorithm;
        /**
         * UKM required at init, or null for a cell whose no-spec
         * {@code init(Key)} works (every cell but the CKDF one). Non-null on
         * a cell means every "drive with the cell's own valid key" call site
         * carries a UKM spec instead of the bare no-spec init — RFC 6637 §8
         * makes it mandatory, so {@code init(Key)} alone always refuses now.
         * A fault call site that deliberately substitutes a DIFFERENT key or
         * spec (wrong-family key, null key, a foreign param spec) is
         * unaffected — that substitution IS the fault under test.
         */
        final byte[] initUkm;
        /**
         * Non-null only for the RFC 9580 hybrid-HKDF cells: T, wrapped
         * together with the (mandatory) UKM into a
         * {@code HybridValueParameterSpec} rather than a bare UKM spec. The
         * UKM field doubles as the HKDF info string for these cells.
         */
        final byte[] hybridT;

        Cell(String name, String spiClass, String kpg, String kf, String secretAlgorithm)
        {
            this(name, spiClass, kpg, kf, secretAlgorithm, null, null);
        }

        Cell(String name, String spiClass, String kpg, String kf, String secretAlgorithm,
                byte[] initUkm)
        {
            this(name, spiClass, kpg, kf, secretAlgorithm, initUkm, null);
        }

        Cell(String name, String spiClass, String kpg, String kf, String secretAlgorithm,
                byte[] initUkm, byte[] hybridT)
        {
            this.name = name;
            this.spiClass = spiClass;
            this.kpgAlgorithm = kpg;
            this.bcKeyFactory = kf;
            this.secretAlgorithm = secretAlgorithm;
            this.initUkm = initUkm;
            this.hybridT = hybridT;
        }
    }

    /**
     * The UKM spec type is provider-specific (BC refuses Jostle's own
     * {@code UserKeyingMaterialSpec} as foreign, and vice versa) — resolve it
     * at the point of use rather than storing one on the cell.
     */
    private static java.security.spec.AlgorithmParameterSpec ukmSpec(Provider p, byte[] ukm)
    {
        return p == bc
                ? new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(ukm)
                : new org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec(ukm);
    }

    /**
     * The cell's required init spec: a bare UKM spec, or (hybrid cells) that
     * UKM spec wrapped as the HKDF info inside a provider-appropriate
     * {@code HybridValueParameterSpec} carrying the cell's fixed T.
     */
    private static java.security.spec.AlgorithmParameterSpec initSpec(Provider p, Cell cell)
    {
        java.security.spec.AlgorithmParameterSpec ukm = ukmSpec(p, cell.initUkm);
        if (cell.hybridT == null)
        {
            return ukm;
        }
        return p == bc
                ? new org.bouncycastle.jcajce.spec.HybridValueParameterSpec(cell.hybridT, true, ukm)
                : new org.openssl.jostle.jcajce.spec.HybridValueParameterSpec(cell.hybridT, true, ukm);
    }

    /** Init with the cell's own valid key, carrying its UKM when it requires one. */
    private static void init(KeyAgreement k, Provider p, PrivateKey priv, Cell cell) throws Exception
    {
        if (cell.initUkm != null)
        {
            k.init(priv, initSpec(p, cell));
        }
        else
        {
            k.init(priv);
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
        c.add(new Cell("DH", "DHKeyAgreementSpi", "DH", "DH", AES256_WRAP));
        c.add(new Cell("DHWITHRFC2631KDF", "DHWithKDFKeyAgreementSpi", "DH", "DH", AES256_WRAP));
        c.add(new Cell("ECDH", "ECDHKeyAgreementSpi", "EC", "EC", AES256_WRAP));
        c.add(new Cell("ECDHWITHSHA256KDF", "ECWithKDFKeyAgreementSpi", "EC", "EC", AES256_WRAP));
        c.add(new Cell("ECCDHWITHSHA256CKDF", "ECWithCKDFKeyAgreementSpi", "EC", "EC", AES256_WRAP, CKDF_UKM));
        c.add(new Cell("X25519WITHSHA256CKDF", "XDHWithCKDFKeyAgreementSpi", "X25519", "X25519", AES256_WRAP, CKDF_UKM));
        c.add(new Cell("X448WITHSHA256CKDF", "XDHWithCKDFKeyAgreementSpi", "X448", "X448", AES256_WRAP, CKDF_UKM));
        c.add(new Cell("X25519", "XDHKeyAgreementSpi", "X25519", "X25519", AES256_WRAP));
        c.add(new Cell("X448", "XDHKeyAgreementSpi", "X448", "X448", AES256_WRAP));
        c.add(new Cell("XDH", "XDHKeyAgreementSpi", "X25519", "XDH", AES256_WRAP));
        // RFC 8418. One SPI serves all three digests, so all three are named:
        // a single cell would leave two registered names unexercised.
        c.add(new Cell("XDHwithSHA256HKDF", "XDHWithHKDFKeyAgreementSpi", "X25519", "X25519", AES256_WRAP));
        c.add(new Cell("XDHwithSHA384HKDF", "XDHWithHKDFKeyAgreementSpi", "X25519", "X25519", AES256_WRAP));
        c.add(new Cell("XDHwithSHA512HKDF", "XDHWithHKDFKeyAgreementSpi", "X25519", "X25519", AES256_WRAP));
        // RFC 9580 v6 hybrid HKDF. The curve fixes the digest, so exactly
        // two names exist; the UKM field carries the fixed HKDF info string
        // and hybridT is a fixed-length filler (its value is unchecked here
        // — only exception shape is under survey, not KEK correctness).
        c.add(new Cell("X25519withSHA256HKDF", "XDHWithHybridHKDFKeyAgreementSpi", "X25519", "X25519",
                AES256_WRAP, "OpenPGP X25519".getBytes(StandardCharsets.US_ASCII), hybridT(64)));
        c.add(new Cell("X448withSHA512HKDF", "XDHWithHybridHKDFKeyAgreementSpi", "X448", "X448",
                AES256_WRAP, "OpenPGP X448".getBytes(StandardCharsets.US_ASCII), hybridT(112)));
        return c;
    }

    private static byte[] hybridT(int len)
    {
        byte[] t = new byte[len];
        for (int i = 0; i < len; i++)
        {
            t[i] = (byte) i;
        }
        return t;
    }

    // ------------------------------------------------------------------

    static final class Pair
    {
        final KeyPair a;
        final KeyPair b;
        final PrivateKey bcA;
        final PublicKey bcB;
        final PublicKey bcAPub;

        Pair(KeyPair a, KeyPair b, PrivateKey bcA, PublicKey bcB, PublicKey bcAPub)
        {
            this.a = a;
            this.b = b;
            this.bcA = bcA;
            this.bcB = bcB;
            this.bcAPub = bcAPub;
        }

        PrivateKey priv(Provider p)
        {
            return p == jsl ? a.getPrivate() : bcA;
        }

        PublicKey peer(Provider p)
        {
            return p == jsl ? b.getPublic() : bcB;
        }

        PublicKey own(Provider p)
        {
            return p == jsl ? a.getPublic() : bcAPub;
        }
    }

    private static final Map<String, Pair> CACHE = new TreeMap<String, Pair>();

    private static Pair keys(Cell cell) throws Exception
    {
        Pair p = CACHE.get(cell.kpgAlgorithm + "/" + cell.bcKeyFactory);
        if (p != null)
        {
            return p;
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(cell.kpgAlgorithm, jsl);
        if ("DH".equals(cell.kpgAlgorithm))
        {
            g.initialize(2048);
        }
        else if ("EC".equals(cell.kpgAlgorithm))
        {
            g.initialize(new ECGenParameterSpec("P-256"));
        }
        KeyPair a = g.generateKeyPair();
        KeyPair b = g.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(cell.bcKeyFactory, bc);
        p = new Pair(a, b,
                kf.generatePrivate(new PKCS8EncodedKeySpec(a.getPrivate().getEncoded())),
                kf.generatePublic(new X509EncodedKeySpec(b.getPublic().getEncoded())),
                kf.generatePublic(new X509EncodedKeySpec(a.getPublic().getEncoded())));
        CACHE.put(cell.kpgAlgorithm + "/" + cell.bcKeyFactory, p);
        return p;
    }

    /** A keypair of a different family, per provider. */
    private static Pair foreign(Cell cell) throws Exception
    {
        return keys("EC".equals(cell.kpgAlgorithm)
                ? new Cell("x", "x", "X25519", "X25519", AES256_WRAP)
                : new Cell("x", "x", "EC", "EC", AES256_WRAP));
    }

    /**
     * Finish under one form.
     *
     * <p>BUFFER hands the provider ONE oversize buffer and takes the returned
     * length. Never sized from a prior RAW: three finishing faults have no
     * successful RAW before them.
     *
     * <p>The buffer is random-filled and snapshotted, and every byte past the
     * reported length must be unchanged. A single sentinel byte would carry a
     * one-in-256 false-pass rate against essentially uniform output.
     */
    private static byte[] finish(KeyAgreement k, Cell cell, Form form, String ctx,
            List<String> tail) throws Exception
    {
        switch (form)
        {
            case RAW:
                return k.generateSecret();
            case NAMED:
                return k.generateSecret(cell.secretAlgorithm).getEncoded();
            case BUFFER:
            {
                byte[] buf = new byte[BUFFER_CAPACITY];
                SR.nextBytes(buf);
                byte[] before = buf.clone();
                int n = k.generateSecret(buf, 0);
                if (n < 0 || n > buf.length)
                {
                    tail.add(ctx + ": reported length " + n + " for a buffer of " + buf.length);
                    return new byte[0];
                }
                for (int i = n; i < buf.length; i++)
                {
                    if (buf[i] != before[i])
                    {
                        tail.add(ctx + ": wrote at " + i + ", past the reported length " + n);
                        break;
                    }
                }
                return Arrays.copyOf(buf, n);
            }
            default:
                throw new IllegalStateException("no finish form: " + form);
        }
    }

    /** Both halves of a repeated finish, so the row is a function of both. */
    private static byte[] concat(byte[] a, byte[] b)
    {
        if (a == null)
        {
            return b;
        }
        if (b == null)
        {
            return a;
        }
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static Observation baseline(Provider p, Cell cell, Pair keys, Form form,
            List<String> tail)
    {
        String ctx = p.getName() + " " + cell.name + " (baseline) " + form;
        return Observer.observe(() -> {
            KeyAgreement k = KeyAgreement.getInstance(cell.name, p);
            init(k, p, keys.priv(p), cell);
            k.doPhase(keys.peer(p), true);
            return finish(k, cell, form, ctx, tail);
        });
    }

    private static Observation applyFault(Provider p, Cell cell, Fault f, Form form,
            Pair keys, List<String> tail) throws Exception
    {
        Pair other = foreign(cell);
        String ctx = p.getName() + " " + cell.name + " " + f + " " + form;
        return Observer.observe(() -> {
            KeyAgreement k = KeyAgreement.getInstance(cell.name, p);
            switch (f)
            {
                case NULL_KEY_INIT:
                    k.init((PrivateKey) null);
                    return null;
                case WRONG_FAMILY_KEY_INIT:
                    k.init(other.priv(p));
                    return null;
                case PUBLIC_KEY_FOR_INIT:
                    k.init((PrivateKey) (Object) keys.own(p));
                    return null;
                case FOREIGN_PARAM_SPEC_INIT:
                    k.init(keys.priv(p), new IvParameterSpec(new byte[16]));
                    return null;
                case DOPHASE_BEFORE_INIT:
                    k.doPhase(keys.peer(p), true);
                    return null;
                case GENERATE_SECRET_BEFORE_INIT:
                    return finish(k, cell, form, ctx, tail);
                case GENERATE_SECRET_BEFORE_DOPHASE:
                    init(k, p, keys.priv(p), cell);
                    return finish(k, cell, form, ctx, tail);
                case NULL_PUBLIC_KEY_DOPHASE:
                    init(k, p, keys.priv(p), cell);
                    k.doPhase(null, true);
                    return null;
                case WRONG_FAMILY_PUBLIC_KEY_DOPHASE:
                    init(k, p, keys.priv(p), cell);
                    k.doPhase(other.peer(p), true);
                    return null;
                case OWN_PUBLIC_KEY_DOPHASE:
                    // Not malformed - a caller agreeing with itself. Legal
                    // arithmetic, so a refusal here would be a policy choice
                    // and worth knowing about on both sides.
                    init(k, p, keys.priv(p), cell);
                    k.doPhase(keys.own(p), true);
                    return finish(k, cell, form, ctx, tail);
                case DOPHASE_NOT_LAST_THEN_GENERATE:
                    init(k, p, keys.priv(p), cell);
                    k.doPhase(keys.peer(p), false);
                    return finish(k, cell, form, ctx, tail);
                case GENERATE_SECRET_TWICE:
                {
                    init(k, p, keys.priv(p), cell);
                    k.doPhase(keys.peer(p), true);
                    // The row covers both results.
                    byte[] s1 = finish(k, cell, form, ctx, tail);
                    byte[] s2 = finish(k, cell, form, ctx, tail);
                    return concat(s1, s2);
                }
                case SHORT_OUTPUT_GENERATE_SECRET:
                {
                    init(k, p, keys.priv(p), cell);
                    k.doPhase(keys.peer(p), true);
                    // Deliberately undersized: the capacity IS the probe,
                    // so this does not use the survey's oversize buffer.
                    byte[] out = new byte[1];
                    k.generateSecret(out, 0);
                    return out;
                }
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    @Test
    public void surveyKeyAgreementNegativePaths() throws Exception
    {
        List<String> rows = new ArrayList<String>();
        List<String> tail = new ArrayList<String>();
        Map<ParityVerdict, Integer> tally = new EnumMap<ParityVerdict, Integer>(ParityVerdict.class);
        Map<Form, Integer> perForm = new EnumMap<Form, Integer>(Form.class);
        int measured = 0;
        int expectedRows = 0;
        int noBaseline = 0;

        for (Cell cell : cells())
        {
            Pair keys = keys(cell);

            // One probe settles whether BouncyCastle serves the algorithm at
            // all. getInstance decides that before any form is reached, so it
            // is a single row and the cell contributes nothing further.
            ParityResult raw = ExceptionParity.classify(
                    baseline(jsl, cell, keys, Form.RAW, tail),
                    baseline(bc, cell, keys, Form.RAW, tail));
            if (raw.verdict() == ParityVerdict.BC_ABSENT)
            {
                rows.add(row(cell, Form.NONE, "(baseline)", raw));
                bump(tally, raw.verdict());
                bumpForm(perForm, Form.NONE);
                expectedRows += 1;
                continue;
            }

            // A baseline per FORM, and the gate is per form. A cell-wide gate
            // would let one refused form destroy the rows of a working one.
            Map<Form, ParityResult> bases = new EnumMap<Form, ParityResult>(Form.class);
            int formsFailed = 0;
            for (Form form : DRIVEABLE)
            {
                ParityResult b = form == Form.RAW ? raw : ExceptionParity.classify(
                        baseline(jsl, cell, keys, form, tail),
                        baseline(bc, cell, keys, form, tail));
                bases.put(form, b);
                rows.add(row(cell, form, "(baseline)", b));
                bump(tally, b.verdict());
                bumpForm(perForm, form);
                if (b.verdict() != ParityVerdict.MATCH_ACCEPT)
                {
                    formsFailed++;
                }
            }
            // No form completed an agreement, so the form-INDEPENDENT faults
            // are gated as well: a MATCH on a cell that cannot agree at all
            // would read as parity.
            boolean anyForm = formsFailed < DRIVEABLE.size();
            if (!anyForm)
            {
                noBaseline++;
            }
            expectedRows += rowsPerCell();

            for (Fault f : Fault.values())
            {
                for (Form form : f.forms())
                {
                    ParityResult b = bases.get(form);
                    String why = null;
                    if (b != null && b.verdict() != ParityVerdict.MATCH_ACCEPT)
                    {
                        why = "baseline " + form + " was " + b.verdict();
                    }
                    else if (b == null && !anyForm)
                    {
                        why = "no form has a baseline";
                    }
                    if (why != null)
                    {
                        // Recorded, never dropped: a row that measured nothing
                        // must not read as agreement.
                        rows.add(row(cell, form, f.name(), new ParityResult(
                                ParityVerdict.NO_BASELINE, "-", "-", why)));
                        bump(tally, ParityVerdict.NO_BASELINE);
                        bumpForm(perForm, form);
                        continue;
                    }
                    ParityResult r = ExceptionParity.classify(
                            applyFault(jsl, cell, f, form, keys, tail),
                            applyFault(bc, cell, f, form, keys, tail));
                    rows.add(row(cell, form, f.name(), r));
                    bump(tally, r.verdict());
                    bumpForm(perForm, form);
                    measured++;
                }
            }
        }

        StringBuilder sb = new StringBuilder("\n=== MT-31 KeyAgreement negative-path survey ===\n");
        for (String r : rows)
        {
            sb.append(r).append('\n');
        }
        sb.append("--- tally ---\n");
        for (Map.Entry<ParityVerdict, Integer> e : tally.entrySet())
        {
            sb.append(String.format("  %-26s %d%n", e.getKey(), e.getValue()));
        }
        System.out.println(sb);

        // A provider that writes past the length it reported is a defect in
        // that provider, not a parity row, so it fails rather than tallies.
        Assertions.assertTrue(tail.isEmpty(),
                "generateSecret(byte[], int) wrote outside the length it reported: " + tail);

        // DERIVED, never typed: one baseline per driveable form plus each fault
        // once per applicable form, summed over the cells actually driven.
        Assertions.assertEquals(expectedRows, rows.size(),
                "survey produced " + rows.size() + " rows; the catalogue derives " + expectedRows);

        // A form that produced no rows is the vacuity case - "0 rows for
        // BUFFER" reads exactly like "BUFFER is fine".
        for (Form form : DRIVEABLE)
        {
            Integer n = perForm.get(form);
            Assertions.assertTrue(n != null && n > 0,
                    "form " + form + " produced no rows; a form that measured nothing"
                            + " reads exactly like a form that is fine");
        }

        Assertions.assertTrue(measured > 0,
                "survey measured no fault cell at all; it is not measuring the surface");
        Assertions.assertTrue(noBaseline * 3 < cells().size(),
                noBaseline + " of " + cells().size() + " agreements had no working baseline"
                        + " under any form");
    }

    /** Every registered KeyAgreement SPI class reaches a cell. Both directions. */
    @Test
    public void everyKeyAgreementSpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"KeyAgreement".equals(sv.getType()))
            {
                continue;
            }
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
        StringBuilder sb = new StringBuilder("\n=== KeyAgreement SPI-class census ===\n");
        List<String> uncovered = new ArrayList<String>();
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

        Assertions.assertTrue(byClass.size() >= 4,
                "census found only " + byClass.size() + " KeyAgreement SPI classes; not reading the provider");
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if ("KeyAgreement".equals(sv.getType()))
            {
                direct++;
            }
        }
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered KeyAgreement count " + direct);
        Assertions.assertTrue(uncovered.isEmpty(),
                "KeyAgreement SPI classes with no survey cell: " + uncovered);
        Set<String> unknown = new HashSet<String>(covered);
        unknown.removeAll(byClass.keySet());
        Assertions.assertTrue(unknown.isEmpty(),
                "survey cells name SPI classes the provider does not register: " + unknown);
    }

    private static void bump(Map<ParityVerdict, Integer> m, ParityVerdict v)
    {
        Integer n = m.get(v);
        m.put(v, n == null ? 1 : n + 1);
    }

    private static void bumpForm(Map<Form, Integer> m, Form f)
    {
        Integer n = m.get(f);
        m.put(f, n == null ? 1 : n + 1);
    }

    private static String row(Cell cell, Form form, String fault, ParityResult r)
    {
        String f = form == Form.NONE ? "-" : form.name();
        String head = String.format("%-20s %-6s %-32s %-26s ours=%-32s bc=%-32s %s",
                cell.name, f, fault, r.verdict(), simple(r.ourType()), simple(r.bcType()),
                r.qualifier());
        if (!r.isDivergence())
        {
            return head;
        }
        return head + "\n" + String.format("%-20s %-6s %-32s   ours: %s%n%-20s %-6s %-32s     bc: %s",
                "", "", "", blank(r.ourMessage()), "", "", "", blank(r.bcMessage()));
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
