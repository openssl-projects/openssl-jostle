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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

/**
 * MT-31 Group C, arc 3a: our exception type against BouncyCastle's and the
 * JDK's, for every registered KeyStore name and every negative path.
 *
 * <h2>Provider scope, read live rather than recalled</h2>
 *
 * <p>JSL registers four KeyStore names; <b>JSLFIPS registers none</b> (measured
 * 2026-09-07 against the 3.5.8 module: JSLFIPS serves 274 services across 13
 * types, and KeyStore is not one of them). So this survey has no FIPS twin, and
 * it does not gate on a module - the absence is structural, not conditional.
 * The JDK serves only {@code PKCS12} of the four, so three names are
 * two-provider and land UNATTRIBUTED by construction.
 *
 * <h2>Four of the fourteen faults are CONTROLS, not measurements</h2>
 *
 * <p>{@code java.security.KeyStore} carries twenty
 * {@code throw new KeyStoreException("Uninitialized keystore")} sites, every one
 * inside a {@code final} method that checks its {@code initialized} flag BEFORE
 * dispatching to the SPI (JDK 25 {@code src.zip},
 * {@code java.base/java/security/KeyStore.java}, and {@code store} enforces the
 * same at its own head). The four {@code UNINIT_*} faults therefore never reach
 * any provider.
 *
 * <p>They are kept deliberately, in {@link #CONTROL_FAULTS}, and
 * {@link #uninitialisedFaultsAreJdkEnforcedControls()} requires them to be
 * ALL_AGREE. That is MT-42's control-row shape: they prove the harness reaches
 * the provider layer on the OTHER cells. <b>A control that DIVERGES means the
 * harness is broken, not that a provider is</b> - which is the opposite
 * diagnosis from every other row in the table, so it gets its own test rather
 * than being buried in the tally.
 *
 * <p>The survey's MEASURING count is therefore 40, not 56.
 *
 * <h2>Three cells are deliberate divergences, pinned with their contract</h2>
 *
 * <p>See {@link #surveyKeyStoreNegativePaths()} for the per-cell notes. The JCA
 * javadoc is the oracle on all three, because the question there is what
 * {@code load} and {@code store} are contractually permitted to do - not what
 * any provider happens to do.
 */
public class KeyStoreNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;

    private static final char[] PW = "correct-horse-battery-staple".toCharArray();
    private static final char[] WRONG_PW = "not-the-password".toCharArray();

    /** A conventional PKCS12, built by the JDK so it is nobody's dialect. */
    private static byte[] conventionalP12;

    /**
     * The fault axis. Fourteen entries; the four {@code UNINIT_*} are controls.
     */
    enum Fault
    {
        UNINIT_GETKEY,
        UNINIT_ALIASES,
        UNINIT_SIZE,
        UNINIT_STORE,
        LOAD_NULL_PASSWORD,
        LOAD_WRONG_PASSWORD,
        LOAD_TRUNCATED,
        LOAD_GARBAGE,
        LOAD_EMPTY,
        LOAD_TRAILING_GARBAGE,
        STORE_NULL_STREAM,
        GETKEY_NULL_ALIAS,
        GETKEY_ABSENT_ALIAS,
        SETCERT_NULL_CERT
    }

    private static final TreeSet<Fault> CONTROL_FAULTS = new TreeSet<Fault>(java.util.Arrays.asList(
            Fault.UNINIT_GETKEY, Fault.UNINIT_ALIASES, Fault.UNINIT_SIZE, Fault.UNINIT_STORE));

    /**
     * The fixture certificate, copied verbatim from
     * {@code X509CertificateFactoryTest}. Extracted by script rather than
     * retyped, and independently base64-decoded to a DER SEQUENCE before use.
     */
    private static final String CERT_B64 =
            "MIIDFTCCAf2gAwIBAgIUVSbA2ohOLE8j05vqRp0HoFCgcYcwDQYJKoZIhvcNAQEL"
          + "BQAwGjEYMBYGA1UEAwwPSm9zdGxlIFJTQSBUZXN0MB4XDTI2MDYwNTIzNTA1NloX"
          + "DTM2MDYwMjIzNTA1NlowGjEYMBYGA1UEAwwPSm9zdGxlIFJTQSBUZXN0MIIBIjAN"
          + "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtA9sLfgO1/dW9q1w/dyoox6S0C6l"
          + "fWYIwtr+kiuJicBfQ+0Bqm1XRqVhmLUTSadxLMbEY+rQ0Hyq0YNQrgKME68pbX1k"
          + "FQcNk3aS/a+aJ7J2XG/yZih5rHhgxKIjaGDfsBdQPlTueC8IV+3v+h8SweYuOv5y"
          + "aXKcxk+IeN/MzSag/2YqDsBzmN98R0hAGvvVsU9KN6OydTSqDAGJ0ontBoJmqj3N"
          + "5bdwImikjVSYC65frTMcvFgO2gOrRHiMCuqxhR0wLhn2AZote/LdUMIrIhB2wMOQ"
          + "1NiIN1jET8TN9FSVDXjlK+MFRWopx8rdtg3h7Egs1U6WsBQ8jOTQIASm1wIDAQAB"
          + "o1MwUTAdBgNVHQ4EFgQUTlapRpnUiPa9hzCribOp+lqpScgwHwYDVR0jBBgwFoAU"
          + "TlapRpnUiPa9hzCribOp+lqpScgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B"
          + "AQsFAAOCAQEAIS/foqm1TkS68DNfElAWhaabpP8/TBpNF5VTYgMHp9H/NGprGUm5"
          + "DXngGRQgN7WwsJVhuhJJP58qGOVjsuZlwXhN/65l3xDof9JuEAeGGJKkfJZfaF3b"
          + "6mDVlM2m3VCNcCRiuJqllDy/L6/D3t5WFxSizDGM4gYObX3tFnm4keiEohE2gZ8+"
          + "KpudoyLOnsEBxBO/Xv9+cQlfkoU7Pd6N+bDZ6HpoDkFp29iVxtRhPign+5HAl03J"
          + "4BVccBXua58I57YzhfP1YDD1DKK8H3SKzaHTrUkZBZkvAEvmIkOKIIOvJRjkXGlA"
          + "V806dyTKN7aECu5CPJLm9ZlxyuBPFTBE0w==";

    /**
     * Every live name has a reference, so PINNED and BLOCKED are empty HERE -
     * established by measurement, not assumed: BouncyCastle serves all four.
     * The tri-state is still carried because {@link #nameAccountingIsComplete()}
     * is what makes an empty PINNED set a MEASURED fact rather than an omission,
     * and because a name added later may have no reference at all.
     */
    private static final TreeSet<String> PINNED = new TreeSet<String>();
    private static final TreeSet<String> BLOCKED = new TreeSet<String>();

    @BeforeAll
    public static void setUp() throws Exception
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
        conventionalP12 = buildConventionalP12();
    }

    /**
     * A PKCS12 written by the JDK's own implementation.
     *
     * <p>Built by the JDK deliberately. A keystore we wrote ourselves would make
     * every load cell a round-trip through our own dialect, and the PBMAC1
     * history is the reason that matters: {@code store()} succeeded while no
     * conventional {@code .p12} could be READ.
     */
    private static byte[] buildConventionalP12() throws Exception
    {
        Provider jdk = JdkComparator.forService("KeyStore", "PKCS12");
        Assertions.assertNotNull(jdk, "no JDK PKCS12 provider; the fixture cannot be built");
        Provider certJdk = JdkComparator.forService("CertificateFactory", "X.509");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", certJdk);
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(
                Base64.getDecoder().decode(CERT_B64)));

        KeyStore ks = KeyStore.getInstance("PKCS12", jdk);
        ks.load(null, PW);
        ks.setCertificateEntry("thecert", cert);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        ks.store(bo, PW);
        byte[] p12 = bo.toByteArray();
        Assertions.assertTrue(p12.length > 64, "fixture keystore is implausibly small: " + p12.length);
        return p12;
    }

    static List<String> names()
    {
        List<String> l = new ArrayList<String>();
        for (Provider.Service sv : jsl.getServices())
        {
            if ("KeyStore".equals(sv.getType()))
            {
                l.add(sv.getAlgorithm());
            }
        }
        Collections.sort(l);
        return l;
    }

    private static Observation applyFault(Provider p, String name, Fault f)
    {
        return Observer.observe(() -> {
            switch (f)
            {
                case UNINIT_GETKEY:
                {
                    Object k = KeyStore.getInstance(name, p).getKey("a", PW);
                    return k == null ? null : new byte[0];
                }
                case UNINIT_ALIASES:
                    KeyStore.getInstance(name, p).aliases();
                    return null;
                case UNINIT_SIZE:
                    KeyStore.getInstance(name, p).size();
                    return null;
                case UNINIT_STORE:
                    KeyStore.getInstance(name, p).store(new ByteArrayOutputStream(), PW);
                    return null;
                case LOAD_NULL_PASSWORD:
                    return load(p, name, conventionalP12, null);
                case LOAD_WRONG_PASSWORD:
                    return load(p, name, conventionalP12, WRONG_PW);
                case LOAD_TRUNCATED:
                    return load(p, name, Arrays.copyOf(conventionalP12, conventionalP12.length / 2), PW);
                case LOAD_GARBAGE:
                    return load(p, name, new byte[]{9, 9, 9, 9, 9, 9, 9, 9}, PW);
                case LOAD_EMPTY:
                    return load(p, name, new byte[0], PW);
                case LOAD_TRAILING_GARBAGE:
                    return load(p, name, Arrays.copyOf(conventionalP12, conventionalP12.length + 4), PW);
                case STORE_NULL_STREAM:
                {
                    KeyStore ks = KeyStore.getInstance(name, p);
                    ks.load(null, PW);
                    ks.store(null, PW);
                    return null;
                }
                case GETKEY_NULL_ALIAS:
                {
                    KeyStore ks = KeyStore.getInstance(name, p);
                    ks.load(null, PW);
                    Object k = ks.getKey(null, PW);
                    return k == null ? null : new byte[0];
                }
                case GETKEY_ABSENT_ALIAS:
                {
                    KeyStore ks = KeyStore.getInstance(name, p);
                    ks.load(null, PW);
                    Object k = ks.getKey("no-such-alias", PW);
                    return k == null ? null : new byte[0];
                }
                case SETCERT_NULL_CERT:
                {
                    KeyStore ks = KeyStore.getInstance(name, p);
                    ks.load(null, PW);
                    ks.setCertificateEntry("x", null);
                    return null;
                }
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    private static byte[] load(Provider p, String name, byte[] bytes, char[] pw) throws Exception
    {
        KeyStore ks = KeyStore.getInstance(name, p);
        ks.load(new ByteArrayInputStream(bytes), pw);
        return null;
    }

    /**
     * The table.
     *
     * <p>Three cells are deliberate divergences of ours, each pinned against the
     * contract rather than against a provider:
     *
     * <ol>
     *   <li><b>LOAD_NULL_PASSWORD</b> - we raise {@code IOException}, the JDK
     *       ACCEPTS, BouncyCastle raises a raw {@code NullPointerException}.
     *       {@code KeyStore.load}'s javadoc permits BOTH of the first two:
     *       <i>"If a password is not given for integrity checking, then integrity
     *       checking is not performed"</i> AND {@code @throws IOException ... if
     *       a password is required but not given}. So our refusal is
     *       contract-legal and so is the JDK's acceptance; we pin the strict
     *       reading. BouncyCastle's NPE is legal on neither - a bundle row.</li>
     *   <li><b>LOAD_TRAILING_GARBAGE</b> - we alone refuse. Ours is the
     *       {@code d2i} consumed-length rule (see the "{@code d2i_*} accepts
     *       trailing garbage" section of {@code .claude/guides/native-code.md});
     *       the check is {@code interface/nonfips/util/ks.c} returning
     *       {@code JO_DER_TRAILING_DATA} ({@code -138},
     *       {@code interface/nonfips/util/bc_err_codes.h}), surfaced as
     *       {@code Asn1TrailingDataException("DER encoding has trailing data")}
     *       by {@code DefaultServiceNI} and translated to {@code IOException} by
     *       the SPI, which is what {@code load} declares. Being stricter than
     *       both references is the safe direction and is pinned as such.</li>
     *   <li><b>STORE_NULL_STREAM</b> - we raise the {@code IOException} that
     *       {@code store} declares; BOTH references raise an undeclared
     *       {@code NullPointerException}. The BC-parity rule's boundary applies:
     *       where the references diverge from the JCE contract, JCE-canonical
     *       wins.</li>
     * </ol>
     */
    @Test
    public void surveyKeyStoreNegativePaths()
    {
        SurveyReport report = new SurveyReport("MT-31 Group C KeyStore negative-path survey");
        List<String> names = names();

        for (String name : names)
        {
            Provider jdk = JdkComparator.forService("KeyStore", name);
            report.note(String.format("%-24s (comparability)  bc=%s  jdk=%s", name,
                    bc.getService("KeyStore", name) == null ? "absent" : "present",
                    jdk == null ? "absent" : jdk.getName()));

            for (Fault f : Fault.values())
            {
                report.cell(name, f.name(), ThreeWay.classify(
                        applyFault(jsl, name, f),
                        bc.getService("KeyStore", name) == null
                                ? Observation.absent() : applyFault(bc, name, f),
                        jdk == null ? Observation.absent() : applyFault(jdk, name, f)));
            }
        }
        // Absolute floor, per SurveyReport's class note: four names times
        // fourteen faults. Absolute so that discovery silently returning fewer
        // names cannot shrink the floor with it.
        report.assertMeasured(56, names.size(), 0);
    }

    /**
     * The four {@code UNINIT_*} faults are enforced by {@code java.security.KeyStore}
     * before any SPI is reached, so every provider must answer identically.
     *
     * <p>A divergence here is a broken HARNESS, not a broken provider - the
     * opposite diagnosis from the rest of the table, which is why it is asserted
     * separately and not folded into the tally.
     *
     * <p>The asserted property is NO DIVERGENCE, plus ALL_AGREE on the cells that
     * actually have three comparators. ALL_AGREE alone would be wrong, and was:
     * the JDK serves only {@code PKCS12}, so the twelve cells on the other three
     * names are NOT_ATTRIBUTABLE however perfectly they agree.
     */
    @Test
    public void uninitialisedFaultsAreJdkEnforcedControls()
    {
        List<String> mismatches = new ArrayList<String>();
        int checked = 0;
        int attributable = 0;
        for (String name : names())
        {
            Provider jdk = JdkComparator.forService("KeyStore", name);
            for (Fault f : CONTROL_FAULTS)
            {
                ThreeWay r = ThreeWay.classify(
                        applyFault(jsl, name, f),
                        bc.getService("KeyStore", name) == null
                                ? Observation.absent() : applyFault(bc, name, f),
                        jdk == null ? Observation.absent() : applyFault(jdk, name, f));
                checked++;
                // The property is NO DIVERGENCE; ALL_AGREE needs three
                // comparators and only PKCS12 has them.
                if (r.isDivergence())
                {
                    mismatches.add(r.row(name, f.name()));
                }
                if (jdk != null)
                {
                    attributable++;
                    if (r.attribution() != ThreeWay.Attribution.ALL_AGREE)
                    {
                        mismatches.add(r.row(name, f.name()));
                    }
                }
            }
        }
        Assertions.assertTrue(checked >= 16,
                "control census checked only " + checked + " cells; it is not reading the provider");
        // Non-vacuity: at least one name must carry all three comparators, or the
        // ALL_AGREE half of this control never executes.
        Assertions.assertTrue(attributable >= 4,
                "no KeyStore name had a JDK comparator, so the three-way half of this"
                        + " control measured nothing; attributable=" + attributable);
        Assertions.assertTrue(mismatches.isEmpty(),
                "JDK-enforced control cells diverged, so the HARNESS is wrong, not a provider:\n"
                        + String.join("\n", mismatches));
    }

    /**
     * The three deliberate divergences, ASSERTED - because the survey does not.
     *
     * <p>{@link #surveyKeyStoreNegativePaths()} records cells into a
     * {@link SurveyReport} and asserts only the measured floor, so it is a
     * MEASUREMENT: if we started accepting trailing garbage, or stopped raising
     * {@code IOException} on a null output stream, it would stay green and only
     * the printed report would change. A pin is an assertion with BOTH halves,
     * and this is it. The survey stays as it is; the two have different jobs.
     *
     * <p><b>Asserting the references' behaviour is deliberate, not incidental.</b>
     * A bcprov or JDK bump that moves a reference FAILS this test loudly, which
     * is what a pin is for - the reason a divergence was accepted may have moved
     * with it.
     */
    @Test
    public void pinnedDivergences()
    {
        Provider jdk = JdkComparator.forService("KeyStore", "PKCS12");
        Assertions.assertNotNull(jdk, "no JDK PKCS12 provider; the JDK half of these pins cannot run");

        // 1. A null password. KeyStore.load's javadoc permits BOTH answers:
        //    "If a password is not given for integrity checking, then integrity
        //    checking is not performed" AND "@throws IOException ... if a
        //    password is required but not given". We take the strict reading;
        //    the JDK takes the lenient one. BouncyCastle's raw NPE is legal on
        //    neither reading - the bundle row.
        refuses(jsl, "PKCS12", Fault.LOAD_NULL_PASSWORD, java.io.IOException.class);
        accepts(jdk, "PKCS12", Fault.LOAD_NULL_PASSWORD);
        refuses(bc, "PKCS12", Fault.LOAD_NULL_PASSWORD, NullPointerException.class);

        // 2. Trailing garbage after a well-formed keystore. We alone refuse, on
        //    every name - the d2i consumed-length rule (native-code.md), via
        //    interface/nonfips/util/ks.c returning JO_DER_TRAILING_DATA (-138),
        //    surfaced as Asn1TrailingDataException and translated to the
        //    IOException that load declares. Stricter than both references is
        //    the safe direction; lenient acceptance masks corruption.
        for (String name : names())
        {
            refuses(jsl, name, Fault.LOAD_TRAILING_GARBAGE, java.io.IOException.class);
        }
        accepts(bc, "PKCS12", Fault.LOAD_TRAILING_GARBAGE);
        accepts(jdk, "PKCS12", Fault.LOAD_TRAILING_GARBAGE);

        // 3. A null output stream. store declares IOException; both references
        //    raise an undeclared unchecked NPE. The BC-parity boundary applies -
        //    where the references diverge from the contract, JCE-canonical wins.
        refuses(jsl, "PKCS12", Fault.STORE_NULL_STREAM, java.io.IOException.class);
        refuses(bc, "PKCS12", Fault.STORE_NULL_STREAM, NullPointerException.class);
        refuses(jdk, "PKCS12", Fault.STORE_NULL_STREAM, NullPointerException.class);
    }

    /** Assert a provider refuses this cell with EXACTLY this class. */
    private static void refuses(Provider p, String name, Fault f, Class<?> expected)
    {
        Observation o = applyFault(p, name, f);
        Assertions.assertTrue(o.isThrow(),
                p.getName() + " " + name + " " + f + ": expected " + expected.getName()
                        + " but the call was ACCEPTED");
        Assertions.assertEquals(expected, o.thrown().getClass(),
                p.getName() + " " + name + " " + f + ": wrong refusal type"
                        + " (message was: " + o.message() + ")");
    }

    /** Assert a provider ACCEPTS this cell - the other half of a divergence. */
    private static void accepts(Provider p, String name, Fault f)
    {
        Observation o = applyFault(p, name, f);
        Assertions.assertFalse(o.isAbsent(), p.getName() + " does not serve " + name);
        Assertions.assertFalse(o.isThrow(),
                p.getName() + " " + name + " " + f + ": expected acceptance but it refused with "
                        + (o.isThrow() ? o.thrown().getClass().getName() + " / " + o.message() : ""));
    }

    /**
     * Tri-state accounting over the LIVE name set: every registered name is in
     * exactly one of CELL / PINNED / BLOCKED, and no set names something that is
     * not registered.
     *
     * <p>CELL is derived, not listed - it is every live name the survey drove -
     * so the guard cannot be satisfied by editing a list to match.
     */
    @Test
    public void nameAccountingIsComplete()
    {
        TreeSet<String> live = new TreeSet<String>(names());
        TreeSet<String> cell = new TreeSet<String>(live);
        cell.removeAll(PINNED);
        cell.removeAll(BLOCKED);

        for (String n : PINNED)
        {
            Assertions.assertTrue(live.contains(n), "PINNED names an unregistered KeyStore: " + n);
        }
        // A PINNED entry must be JUSTIFIED, not merely listed. Without this, a
        // name MOVED from CELL to PINNED still satisfies the tally and the
        // guard passes while the name is no longer measured against anything -
        // the exclusion-list vacuity trap. PINNED means "no reference serves
        // it", so that is what is re-derived here, every run.
        for (String n : PINNED)
        {
            Assertions.assertNull(bc.getService("KeyStore", n),
                    "PINNED holds " + n + ", but BouncyCastle serves it - it is a CELL,"
                            + " and pinning it silently drops it from the comparison");
            Assertions.assertNull(JdkComparator.forService("KeyStore", n),
                    "PINNED holds " + n + ", but the JDK serves it - it is a CELL,"
                            + " and pinning it silently drops it from the comparison");
        }
        for (String n : BLOCKED)
        {
            Assertions.assertTrue(live.contains(n), "BLOCKED names an unregistered KeyStore: " + n);
        }
        TreeSet<String> both = new TreeSet<String>(PINNED);
        both.retainAll(BLOCKED);
        Assertions.assertTrue(both.isEmpty(), "PINNED and BLOCKED overlap: " + both);

        Assertions.assertEquals(live.size(), cell.size() + PINNED.size() + BLOCKED.size(),
                "tri-state tally does not equal the live KeyStore count; live=" + live
                        + " cell=" + cell + " pinned=" + PINNED + " blocked=" + BLOCKED);
        Assertions.assertEquals(4, live.size(),
                "expected four registered KeyStore names, found " + live);
        // Measured, not assumed: BouncyCastle serves every one, which is why
        // PINNED is empty. If a future name has no reference it belongs in
        // PINNED, and this assertion is what will say so.
        for (String n : cell)
        {
            Assertions.assertNotNull(bc.getService("KeyStore", n),
                    "no reference serves " + n + ", so it cannot be a CELL - move it to PINNED");
        }
    }
}
