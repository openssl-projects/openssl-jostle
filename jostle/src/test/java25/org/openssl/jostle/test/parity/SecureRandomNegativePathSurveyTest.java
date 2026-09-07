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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;

import java.security.DrbgParameters;
import java.security.DrbgParameters.Capability;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

/**
 * MT-31 Group C, arc 3b: our exception type against BouncyCastle's and the
 * JDK's, for every registered {@code SecureRandom} name and every negative path.
 *
 * <p><b>Placement is forced.</b> The JDK column needs {@link DrbgParameters},
 * which is Java 9+, and CLAUDE.md requires such tests in
 * {@code src/test/java25}. So this class runs on {@code unitTest25JNI} and
 * {@code unitTest25FFI} only, not on legs 8/11/17/21.
 *
 * <p><b>The JDK column is reached by CONFIGURATION, not by name.</b> Of our
 * eighteen names BouncyCastle serves one ({@code DEFAULT}) and the JDK serves
 * one ({@code DRBG}), so a name-keyed survey would leave sixteen names
 * UNCOMPARED. SUN's {@code DRBG} is configurable through
 * {@code securerandom.drbg.config}, so the stand-in for each name is SUN's DRBG
 * configured to the mechanism that name denotes - see {@link #sunConfigFor}.
 *
 * <p><b>That property is shared with us, so ours is measured FIRST.</b>
 * {@code DrbgConfig} reads {@code securerandom.drbg.config} too, which means
 * our own {@code DRBG} (and {@code DEFAULT}, its alias) is configured by the
 * very knob used to reach the reference. Setting it while measuring OUR column
 * would report the configured variant instead of the registered default, and a
 * missing restore would contaminate every later cell without failing. Hence:
 * our observation before the property is touched, the set scoped to the SUN
 * call with a {@code finally}, and {@link #propertyIsRestored()} as the
 * invariant.
 *
 * <p><b>{@code DEFAULT} is an alias of {@code DRBG}</b>
 * ({@code src/main/java/.../ProvRand.java:33},
 * {@code src/main/java9/.../ProvRand.java:34} - both copies, per the
 * multi-release rule), and {@code getServices()} reports it as one of eighteen
 * entries, so the live surface is 17 primaries plus one alias. An alias must
 * behave identically to its primary, which
 * {@link #aliasBehavesAsItsPrimary()} asserts. A divergence there is a broken
 * alias or a broken harness, NOT a provider difference - the same diagnosis
 * note the KeyStore controls carry.
 */
public class SecureRandomNegativePathSurveyTest
{
    private static final String TYPE = "SecureRandom";
    private static final String CONFIG_PROPERTY = "securerandom.drbg.config";

    private static Provider jsl;
    private static Provider bc;
    private static Provider sun;

    /**
     * Names with no reference at all: SUN refuses SHA-1 in EVERY mechanism and
     * BouncyCastle serves neither name.
     *
     * <p>Listed here only as the EXPECTED set - {@link #nameAccountingIsComplete()}
     * re-derives the justification by probing, so an entry cannot outlive its
     * reason and a name that gains a reference fails rather than sitting pinned.
     */
    private static final TreeSet<String> PINNED = new TreeSet<String>(
            java.util.Arrays.asList("HASH-DRBG-SHA1", "HMAC-DRBG-SHA1"));

    private static final TreeSet<String> BLOCKED = new TreeSet<String>();

    private String propertyAtStart;

    enum Fault
    {
        SET_SEED_NULL_BYTES,
        NEXT_BYTES_NULL,
        /** Not a fault: a zero-length request is legal. */
        NEXT_BYTES_EMPTY,
        GENERATE_SEED_NEGATIVE,
        /** Not a fault: a zero-byte seed request is legal. */
        GENERATE_SEED_ZERO,
        INSTANTIATE_FOREIGN_PARAMS,
        INSTANTIATE_NULL_PARAMS,
        INSTANTIATE_STRENGTH_ABOVE_MAX,
        INSTANTIATE_STRENGTH_NEGATIVE,
        RESEED_FOREIGN_PARAMS,
        NEXT_BYTES_FOREIGN_PARAMS,
        NEXT_BYTES_PREDICTION_RESISTANCE
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
        sun = Security.getProvider("SUN");
        Assertions.assertNotNull(sun, "the SUN provider is absent; the JDK column cannot be measured");
    }

    @BeforeEach
    public void captureProperty()
    {
        propertyAtStart = Security.getProperty(CONFIG_PROPERTY);
    }

    @AfterEach
    public void propertyIsRestored()
    {
        // Cheap invariant that catches a missing restore anywhere above. The
        // property is shared with our own DRBG, so a leak silently reconfigures
        // the provider under test rather than failing.
        Assertions.assertEquals(propertyAtStart, Security.getProperty(CONFIG_PROPERTY),
                CONFIG_PROPERTY + " was not restored; every later cell would measure a"
                        + " reconfigured provider");
    }

    static List<String> names()
    {
        List<String> l = new ArrayList<String>();
        for (Provider.Service sv : jsl.getServices())
        {
            if (TYPE.equals(sv.getType()))
            {
                l.add(sv.getAlgorithm());
            }
        }
        Collections.sort(l);
        return l;
    }

    /**
     * SUN's {@code securerandom.drbg.config} string for one of our names, or
     * null when the name maps to no JDK mechanism.
     *
     * <p>Mechanism and variant are READ from {@link RandAlgorithm} - the same
     * enum the service itself uses - so the three unsuffixed names take whatever
     * default the registration declares rather than a value copied into this
     * test. Only the spelling map below is local, and it translates between two
     * external vocabularies (OpenSSL's and the JDK's).
     */
    static String sunConfigFor(String name)
    {
        RandAlgorithm alg = null;
        for (RandAlgorithm a : RandAlgorithm.values())
        {
            if (name.equals(a.getJcaName()))
            {
                alg = a;
                break;
            }
        }
        if (alg == null)
        {
            // An alias (DEFAULT) has no enum constant of its own; fall through
            // to its primary rather than reporting no reference.
            if ("DEFAULT".equals(name))
            {
                return sunConfigFor(RandAlgorithm.DRBG.getJcaName());
            }
            return null;
        }
        String mech = jdkMechanism(alg.getMechanism());
        String digestOrCipher = jdkAlgorithm(alg.getVariant());
        if (mech == null || digestOrCipher == null)
        {
            return null;
        }
        return mech + "," + digestOrCipher;
    }

    private static String jdkMechanism(String ours)
    {
        if ("CTR-DRBG".equals(ours)) { return "CTR_DRBG"; }
        if ("HASH-DRBG".equals(ours)) { return "Hash_DRBG"; }
        if ("HMAC-DRBG".equals(ours)) { return "HMAC_DRBG"; }
        return null;
    }

    /** OpenSSL spellings to the JDK's. */
    private static String jdkAlgorithm(String ours)
    {
        if (ours == null) { return null; }
        if (ours.startsWith("AES-"))
        {
            // "AES-256-CTR" -> "AES-256"
            int second = ours.indexOf('-', 4);
            return second < 0 ? ours : ours.substring(0, second);
        }
        if ("SHA1".equals(ours)) { return "SHA-1"; }
        if (ours.startsWith("SHA2-")) { return "SHA-" + ours.substring(5); }
        return null;
    }

    /**
     * Does SUN actually serve this configuration? Probed, never assumed - the
     * SHA-1 configs are well-formed and REFUSED, which is the whole reason the
     * two SHA-1 names are PINNED rather than CELLs.
     */
    static boolean sunServes(String config)
    {
        if (config == null)
        {
            return false;
        }
        String prev = Security.getProperty(CONFIG_PROPERTY);
        try
        {
            Security.setProperty(CONFIG_PROPERTY, config);
            SecureRandom.getInstance("DRBG", sun);
            return true;
        }
        catch (Throwable t)
        {
            return false;
        }
        finally
        {
            Security.setProperty(CONFIG_PROPERTY, prev);
        }
    }

    /** Our column, and BouncyCastle's: taken with the property untouched. */
    static Observation observe(Provider p, String name, Fault f)
    {
        if (p.getService(TYPE, name) == null)
        {
            return Observation.absent();
        }
        return Observer.observe(() -> drive(() -> SecureRandom.getInstance(name, p), name, p, f));
    }

    /** The JDK column: property set only for the duration, restored always. */
    static Observation observeJdk(String name, Fault f)
    {
        String config = sunConfigFor(name);
        if (!sunServes(config))
        {
            return Observation.absent();
        }
        String prev = Security.getProperty(CONFIG_PROPERTY);
        try
        {
            Security.setProperty(CONFIG_PROPERTY, config);
            return Observer.observe(() -> drive(() -> SecureRandom.getInstance("DRBG", sun), "DRBG", sun, f));
        }
        finally
        {
            Security.setProperty(CONFIG_PROPERTY, prev);
        }
    }

    interface Maker
    {
        SecureRandom make() throws Exception;
    }

    private static byte[] drive(Maker m, String name, Provider p, Fault f) throws Throwable
    {
        switch (f)
        {
            case SET_SEED_NULL_BYTES:
                m.make().setSeed((byte[]) null);
                return null;
            case NEXT_BYTES_NULL:
                m.make().nextBytes(null);
                return null;
            case NEXT_BYTES_EMPTY:
                m.make().nextBytes(new byte[0]);
                return null;
            case GENERATE_SEED_NEGATIVE:
                m.make().generateSeed(-1);
                return null;
            case GENERATE_SEED_ZERO:
                m.make().generateSeed(0);
                return null;
            case INSTANTIATE_FOREIGN_PARAMS:
                SecureRandom.getInstance(name, new ForeignParams(), p);
                return null;
            case INSTANTIATE_NULL_PARAMS:
                SecureRandom.getInstance(name, (SecureRandomParameters) null, p);
                return null;
            case INSTANTIATE_STRENGTH_ABOVE_MAX:
                SecureRandom.getInstance(name,
                        DrbgParameters.instantiation(1024, Capability.RESEED_ONLY, null), p);
                return null;
            case INSTANTIATE_STRENGTH_NEGATIVE:
                SecureRandom.getInstance(name,
                        DrbgParameters.instantiation(-2, Capability.RESEED_ONLY, null), p);
                return null;
            case RESEED_FOREIGN_PARAMS:
                m.make().reseed(new ForeignParams());
                return null;
            case NEXT_BYTES_FOREIGN_PARAMS:
                m.make().nextBytes(new byte[8], new ForeignParams());
                return null;
            case NEXT_BYTES_PREDICTION_RESISTANCE:
                m.make().nextBytes(new byte[8], DrbgParameters.nextBytes(-1, true, null));
                return null;
            default:
                throw new IllegalStateException("unhandled fault " + f);
        }
    }

    /** A {@code SecureRandomParameters} implementation no provider knows. */
    static final class ForeignParams implements SecureRandomParameters
    {
    }

    @Test
    public void surveySecureRandomNegativePaths()
    {
        SurveyReport report = new SurveyReport("MT-31 Group C SecureRandom negative-path survey");
        List<String> names = names();

        for (String name : names)
        {
            String config = sunConfigFor(name);
            report.note(String.format("%-20s (comparability)  bc=%-8s jdk-config=%-20s served=%s",
                    name,
                    bc.getService(TYPE, name) == null ? "absent" : "present",
                    config == null ? "(none)" : config,
                    sunServes(config)));

            for (Fault f : Fault.values())
            {
                report.cell(name, f.name(), ThreeWay.classify(
                        observe(jsl, name, f),
                        observe(bc, name, f),
                        observeJdk(name, f)));
            }
        }
        // Absolute floor: eighteen names times twelve faults.
        report.assertMeasured(216, names.size(), 0);
    }

    /**
     * {@code DEFAULT} is an alias of {@code DRBG}, so it must answer identically
     * on every cell.
     *
     * <p>A divergence here is a broken alias or a broken harness, NOT a provider
     * difference - the opposite diagnosis from the rest of the table, which is
     * why it is asserted separately. No external reference can supply this
     * check; it comes free from the registration.
     */
    @Test
    public void aliasBehavesAsItsPrimary()
    {
        List<String> live = names();
        Assertions.assertTrue(live.contains("DEFAULT") && live.contains("DRBG"),
                "DEFAULT and DRBG must both be registered for the alias control to mean anything");

        List<String> mismatches = new ArrayList<String>();
        for (Fault f : Fault.values())
        {
            String primary = describe(observe(jsl, "DRBG", f));
            String alias = describe(observe(jsl, "DEFAULT", f));
            if (!primary.equals(alias))
            {
                mismatches.add(f + ": DRBG=" + primary + " but DEFAULT=" + alias);
            }
        }

        String primaryCeiling = ceilingPattern("DRBG");
        String aliasCeiling = ceilingPattern("DEFAULT");
        if (!primaryCeiling.equals(aliasCeiling))
        {
            mismatches.add("strength ceiling: DRBG=" + primaryCeiling
                    + " but DEFAULT=" + aliasCeiling);
        }

        // Live vacuity guard: prove the ceiling axis actually discriminates, so
        // a green result above cannot come from an axis that says nothing.
        String sha1Ceiling = ceilingPattern("HASH-DRBG-SHA1");
        Assertions.assertNotEquals(primaryCeiling, sha1Ceiling,
                "the strength-ceiling axis does not separate DRBG from HASH-DRBG-SHA1, so it"
                        + " cannot detect a mis-pointed alias either and this control is vacuous");

        Assertions.assertTrue(mismatches.isEmpty(),
                "DEFAULT is an alias of DRBG (ProvRand.java:33 / java9 ProvRand.java:34) yet they"
                        + " answer differently, so the alias or the harness is broken:\n"
                        + String.join("\n", mismatches));
    }

    /**
     * Which instantiation strengths a name accepts, as a comparable string.
     *
     * <p>The only measured axis that SEPARATES our names - all eighteen answer
     * alike on all twelve faults - so it is what makes the alias control
     * non-vacuous rather than a comparison that any two names would pass.
     */
    static String ceilingPattern(String name)
    {
        StringBuilder sb = new StringBuilder();
        for (int strength : new int[]{112, 128, 192, 256})
        {
            boolean ok;
            try
            {
                SecureRandom.getInstance(name,
                        DrbgParameters.instantiation(strength, Capability.RESEED_ONLY, null), jsl);
                ok = true;
            }
            catch (Throwable t)
            {
                ok = false;
            }
            sb.append(ok ? '+' : '-');
        }
        return sb.toString();
    }

    private static String describe(Observation o)
    {
        if (o.isAbsent()) { return "(absent)"; }
        if (o.isThrow()) { return o.thrown().getClass().getName(); }
        return "(accepted)";
    }

    /**
     * The divergences this surface carries, ASSERTED - because the survey does
     * not. The survey records cells and asserts only the measured floor.
     *
     * <h2>MT-67: two cells where the MAJORITY is wrong</h2>
     *
     * <p>On a foreign {@code SecureRandomParameters} we raise
     * {@code UnsupportedOperationException} and so does BouncyCastle, while the
     * JDK raises {@code IllegalArgumentException}. The JDK is
     * CONTRACT-CANONICAL: both {@code reseed(SecureRandomParameters)} and
     * {@code nextBytes(byte[], SecureRandomParameters)} declare
     * {@code UnsupportedOperationException} <i>"if the underlying provider
     * implementation has not overridden this method"</i> and
     * {@code IllegalArgumentException} <i>"if params is null, illegal or
     * unsupported by this SecureRandom"</i>. We HAVE overridden both - measured:
     * {@code reseed()}, {@code reseed(DrbgParameters.reseed(..))} and
     * {@code nextBytes(buf, DrbgParameters.nextBytes(..))} all succeed on all
     * eighteen names - so our exception is in the wrong category.
     *
     * <p><b>{@code ThreeWay} labels these {@code JDK_IS_ODD}, because two
     * providers agree against one, and that label is misleading here.</b>
     * Attribution by vote is not attribution by correctness: a two-against-one
     * row is a pointer to look, never a verdict. Per the java-spi.md boundary -
     * match BouncyCastle's type UNLESS BouncyCastle diverges from the JCE
     * contract - the fix direction is OURS, to
     * {@code IllegalArgumentException}. Registered as MT-67 and NOT fixed here
     * (that is a {@code src/main} change with a product gate); this pin records
     * current behaviour and must NOT be read as endorsing it.
     */
    @Test
    public void pinnedDivergences()
    {

        // Finding D, both halves, on a name every provider can answer.
        refuses(observe(jsl, "DRBG", Fault.RESEED_FOREIGN_PARAMS),
                UnsupportedOperationException.class, "JSL DRBG RESEED_FOREIGN_PARAMS");
        refuses(observeJdk("DRBG", Fault.RESEED_FOREIGN_PARAMS),
                IllegalArgumentException.class, "JDK DRBG RESEED_FOREIGN_PARAMS");
        refuses(observe(bc, "DEFAULT", Fault.RESEED_FOREIGN_PARAMS),
                UnsupportedOperationException.class, "BC DEFAULT RESEED_FOREIGN_PARAMS");

        refuses(observe(jsl, "DRBG", Fault.NEXT_BYTES_FOREIGN_PARAMS),
                UnsupportedOperationException.class, "JSL DRBG NEXT_BYTES_FOREIGN_PARAMS");
        refuses(observeJdk("DRBG", Fault.NEXT_BYTES_FOREIGN_PARAMS),
                IllegalArgumentException.class, "JDK DRBG NEXT_BYTES_FOREIGN_PARAMS");
        refuses(observe(bc, "DEFAULT", Fault.NEXT_BYTES_FOREIGN_PARAMS),
                UnsupportedOperationException.class, "BC DEFAULT NEXT_BYTES_FOREIGN_PARAMS");

        // Prediction resistance: we and the JDK agree, BouncyCastle is odd.
        refuses(observe(jsl, "DRBG", Fault.NEXT_BYTES_PREDICTION_RESISTANCE),
                IllegalArgumentException.class, "JSL DRBG NEXT_BYTES_PREDICTION_RESISTANCE");
        refuses(observeJdk("DRBG", Fault.NEXT_BYTES_PREDICTION_RESISTANCE),
                IllegalArgumentException.class, "JDK DRBG NEXT_BYTES_PREDICTION_RESISTANCE");
        refuses(observe(bc, "DEFAULT", Fault.NEXT_BYTES_PREDICTION_RESISTANCE),
                UnsupportedOperationException.class, "BC DEFAULT NEXT_BYTES_PREDICTION_RESISTANCE");

        // The two positive cells, on every live name. A fault survey is blind to
        // an over-refusal of good input, so these must be asserted or the class
        // doc's claim that they are "carried" is empty.
        for (String name : names())
        {
            accepts(observe(jsl, name, Fault.NEXT_BYTES_EMPTY), "JSL " + name + " NEXT_BYTES_EMPTY");
            accepts(observe(jsl, name, Fault.GENERATE_SEED_ZERO), "JSL " + name + " GENERATE_SEED_ZERO");
        }
    }

    /**
     * The two SHA-1 names, pinned against the JCA contract alone.
     *
     * <p>They have no reference: SUN refuses SHA-1 in every mechanism and
     * BouncyCastle serves neither name. <b>SUN's refusal is recorded as the
     * REFERENCE's position, not as a conformance claim about SHA-1 either way</b>
     * - whether we should serve these names at all is a separate, open question
     * and this test takes no side on it.
     */
    @Test
    public void sha1NamesArePinnedAgainstTheContractAlone()
    {
        for (String name : PINNED)
        {
            Assertions.assertNotNull(jsl.getService(TYPE, name), name + " is not registered");
            Assertions.assertFalse(sunServes(sunConfigFor(name)),
                    "SUN now serves a configuration for " + name + ", so it is a CELL, not PINNED");
            Assertions.assertNull(bc.getService(TYPE, name),
                    "BouncyCastle now serves " + name + ", so it is a CELL, not PINNED");

            // Contract conformance, ours alone: the declared types on the paths
            // the JCA specifies, with no reference to compare against.
            refuses(observe(jsl, name, Fault.NEXT_BYTES_NULL),
                    NullPointerException.class, name + " NEXT_BYTES_NULL");
            refuses(observe(jsl, name, Fault.GENERATE_SEED_NEGATIVE),
                    IllegalArgumentException.class, name + " GENERATE_SEED_NEGATIVE");
            refuses(observe(jsl, name, Fault.INSTANTIATE_NULL_PARAMS),
                    IllegalArgumentException.class, name + " INSTANTIATE_NULL_PARAMS");
            accepts(observe(jsl, name, Fault.NEXT_BYTES_EMPTY), name + " NEXT_BYTES_EMPTY");
        }
    }

    /**
     * Tri-state accounting over the LIVE name set, with the PINNED justification
     * RE-DERIVED by probing rather than listed.
     *
     * <p>A PINNED name must be served by neither BouncyCastle (by name) nor the
     * JDK (by CONFIGURATION). The configuration probe runs here every time, so a
     * pin cannot outlive its reason, and a name moved into PINNED to silence the
     * tally fails instead.
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
            Assertions.assertTrue(live.contains(n), "PINNED names an unregistered SecureRandom: " + n);
            Assertions.assertNull(bc.getService(TYPE, n),
                    "PINNED holds " + n + ", but BouncyCastle serves it - it is a CELL");
            Assertions.assertFalse(sunServes(sunConfigFor(n)),
                    "PINNED holds " + n + ", but the JDK serves a configuration for it"
                            + " (" + sunConfigFor(n) + ") - it is a CELL");
        }
        for (String n : BLOCKED)
        {
            Assertions.assertTrue(live.contains(n), "BLOCKED names an unregistered SecureRandom: " + n);
        }
        TreeSet<String> both = new TreeSet<String>(PINNED);
        both.retainAll(BLOCKED);
        Assertions.assertTrue(both.isEmpty(), "PINNED and BLOCKED overlap: " + both);

        // Every CELL must have at least one reference, or it is mis-classified.
        for (String n : cell)
        {
            boolean hasRef = bc.getService(TYPE, n) != null || sunServes(sunConfigFor(n));
            Assertions.assertTrue(hasRef,
                    "no reference serves " + n + " by name or by configuration, so it cannot be a"
                            + " CELL - move it to PINNED");
        }

        Assertions.assertEquals(live.size(), cell.size() + PINNED.size() + BLOCKED.size(),
                "tri-state tally does not equal the live count; live=" + live
                        + " cell=" + cell + " pinned=" + PINNED + " blocked=" + BLOCKED);
        Assertions.assertEquals(18, live.size(),
                "expected eighteen registered SecureRandom entries (17 primaries + the DEFAULT"
                        + " alias), found " + live);
        Assertions.assertEquals(16, cell.size(), "expected 16 CELL names, got " + cell);
        Assertions.assertEquals(2, PINNED.size(), "expected 2 PINNED names, got " + PINNED);
    }

    private static void refuses(Observation o, Class<?> expected, String where)
    {
        Assertions.assertFalse(o.isAbsent(), where + ": provider does not serve the name");
        Assertions.assertTrue(o.isThrow(),
                where + ": expected " + expected.getName() + " but the call was ACCEPTED");
        Assertions.assertEquals(expected, o.thrown().getClass(),
                where + ": wrong refusal type (message was: " + o.message() + ")");
    }

    private static void accepts(Observation o, String where)
    {
        Assertions.assertFalse(o.isAbsent(), where + ": provider does not serve the name");
        Assertions.assertFalse(o.isThrow(),
                where + ": expected acceptance but it refused with "
                        + (o.isThrow() ? o.thrown().getClass().getName() : ""));
    }
}
