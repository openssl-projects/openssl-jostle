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

import javax.crypto.spec.PBEParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MT-31, Signature surface: measures, for every Signature negative path, the
 * exception TYPE we raise against the type BouncyCastle raises for the identical
 * input - and, where the answer is a boolean, the VALUE each returned.
 *
 * <h2>This is an INSTRUMENT, not a guard</h2>
 *
 * <p>Same contract as {@link CipherNegativePathSurveyTest}: it asserts only that
 * it measured something, and deliberately does NOT assert that divergences are
 * absent. Divergences are pending rulings; a gate here would force premature
 * fixes and make the survey useless for finding the next one.
 *
 * <h2>Verify answers with a BOOLEAN, and that changes everything</h2>
 *
 * <p>A Cipher refuses by throwing. A Signature refuses a bad signature by
 * RETURNING FALSE - measured on both providers for tampered, truncated and
 * garbage input, all four cells false. So an accept/throw classifier is blind
 * here: it would record every correct rejection as an "accept" and could not
 * distinguish it from a wrongly-accepted forgery. {@link Observation#returned}
 * is a fourth observation shape for exactly this, and
 * {@link ParityVerdict#VERIFICATION_DIVERGENCE} - one side accepted what the
 * other refused - is its own SEVERE verdict rather than a row inside
 * {@code DECISION_DIVERGENCE}.
 *
 * <h2>The baseline is BIDIRECTIONAL, and it does four jobs</h2>
 *
 * <p>Each cell first signs with us and verifies with BouncyCastle, AND signs
 * with BouncyCastle and verifies with us, over identical key material and
 * message. That single positive pair is simultaneously:
 *
 * <ol>
 *   <li>the non-vacuity guard - a fault applied on top of a broken baseline
 *       measures nothing about the fault;</li>
 *   <li>the encoding-crossing check - the keys reach BouncyCastle only as
 *       X.509/PKCS#8 encodings through its own KeyFactory, so a mis-encoded
 *       AlgorithmIdentifier fails here rather than silently later;</li>
 *   <li>the WITNESS for the transformation naming - a name that resolved on
 *       both providers but meant different things could not produce a passing
 *       bidirectional cell, so the naming needs no separately-audited alias
 *       table (see {@link SignatureCell});</li>
 *   <li>a differentiator for the verify shape - it is the only cell where a
 *       true is the correct answer, so a verify stubbed to return false fails
 *       the baseline and a verify stubbed to return true fails every fault.</li>
 * </ol>
 */
public class SignatureNegativePathSurveyTest
{
    private static Provider jsl;
    private static Provider bc;
    private static final SecureRandom SR = new SecureRandom();

    /** Faults applied to every applicable cell. */
    enum Fault
    {
        NULL_KEY_SIGN,
        NULL_KEY_VERIFY,
        WRONG_FAMILY_KEY_SIGN,
        WRONG_FAMILY_KEY_VERIFY,
        PUBLIC_KEY_FOR_SIGN,
        PRIVATE_KEY_FOR_VERIFY,
        UNINITIALISED_UPDATE,
        UNINITIALISED_SIGN,
        UNINITIALISED_VERIFY,
        TAMPERED_SIGNATURE,
        TRUNCATED_SIGNATURE,
        GARBAGE_SIGNATURE,
        EMPTY_SIGNATURE,
        TAMPERED_MESSAGE,
        FOREIGN_PARAM_SPEC,
        SET_PARAMETER_AFTER_UPDATE,
        SHORT_OUTPUT_BUFFER,
        REUSE_AFTER_SIGN
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
     * The cell table: at least one representative per SPI class.
     *
     * <p>Which names each class serves, and that every class is represented, is
     * re-derived from {@code getServices()} by {@link #everySignatureSpiClassHasACell}
     * - never asserted from the length of this list.
     */
    static List<SignatureCell> cells()
    {
        PSSParameterSpec pss = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        AlgorithmParameterSpec p256 = new ECGenParameterSpec("P-256");
        List<SignatureCell> c = new ArrayList<SignatureCell>();

        c.add(new SignatureCell("SHA256withRSA", "RSASignatureSpi", "RSA", 2048, null, "RSA", null, null));
        c.add(new SignatureCell("MD5withRSA", "RSASignatureSpi", "RSA", 2048, null, "RSA", null, null));
        c.add(new SignatureCell("NONEwithRSA", "RSASignatureSpi$None", "RSA", 2048, null, "RSA", "SHA-256", null));

        // PSS carries an explicit spec on BOTH providers: our default digest is
        // SHA-256 and BouncyCastle's is SHA-1, a deliberate deviation recorded
        // in java-spi.md. Measured with defaults, both verify directions return
        // false - correct, and useless as a baseline.
        c.add(new SignatureCell("RSASSA-PSS", "RSAPSSSignatureSpi", "RSA", 2048, null, "RSA", null, pss));
        c.add(new SignatureCell("SHA256withRSAandMGF1", "RSAPSSSignatureSpi", "RSA", 2048, null, "RSA", null, null));

        c.add(new SignatureCell("SHA256withECDSA", "ECDSASignatureSpi", "EC", 0, p256, "EC", null, null));
        c.add(new SignatureCell("NONEwithECDSA", "ECDSASignatureSpi", "EC", 0, p256, "EC", "SHA-256", null));

        c.add(new SignatureCell("SHA256withDSA", "DSASignatureSpi", "DSA", 2048, null, "DSA", null, null));
        c.add(new SignatureCell("NONEwithDSA", "DSASignatureSpi", "DSA", 2048, null, "DSA", "SHA-1", null));

        c.add(new SignatureCell("Ed25519", "EdSignatureSpi", "Ed25519", 0, null, "Ed25519", null, null));
        c.add(new SignatureCell("Ed448", "EdSignatureSpi", "Ed448", 0, null, "Ed448", null, null));
        // BouncyCastle resolves no such Signature name: surveyed anyway so the
        // row reads BC_ABSENT rather than the name vanishing from the universe.
        c.add(new SignatureCell("Ed25519ph", "EdSignatureSpi", "Ed25519", 0, null, "Ed25519", null, null));

        c.add(new SignatureCell("ML-DSA-44", "MLDSASignatureSpi", "ML-DSA-44", 0, null, "ML-DSA", null, null));
        c.add(new SignatureCell("ML-DSA-87", "MLDSASignatureSpi", "ML-DSA-87", 0, null, "ML-DSA", null, null));

        c.add(new SignatureCell("SLH-DSA-SHA2-128F", "SLHDSASignatureSpi", "SLH-DSA-SHA2-128F", 0, null, "SLH-DSA", null, null));
        c.add(new SignatureCell("SLH-DSA-SHAKE-128F", "SLHDSASignatureSpi", "SLH-DSA-SHAKE-128F", 0, null, "SLH-DSA", null, null));
        c.add(new SignatureCell("SLH-DSA-PURE", "SLHDSASignatureSpi", "SLH-DSA-SHA2-128F", 0, null, "SLH-DSA", null, null));
        return c;
    }

    /**
     * Registered names this survey deliberately carries NO cell for, with the
     * reason. Named rather than omitted: a universe that shrinks silently is how
     * a survey comes to report everything clean.
     */
    static final Map<String, String> NOT_A_SIGNING_SERVICE = new TreeMap<String, String>();

    static
    {
        NOT_A_SIGNING_SERVICE.put("ML-DSA-CALCULATE-MU",
                "computes mu (64 bytes), not a signature - measured: BouncyCastle's verify of"
                        + " that output is false on BOTH providers' own output, so it has no"
                        + " sign/verify contract to survey");
    }

    // ------------------------------------------------------------------
    // key material
    // ------------------------------------------------------------------

    /** A cell's key material: our pair, plus BouncyCastle's own decoding of it. */
    static final class Keys
    {
        final PrivateKey ourPrivate;
        final PublicKey ourPublic;
        final PrivateKey bcPrivate;
        final PublicKey bcPublic;

        Keys(PrivateKey a, PublicKey b, PrivateKey c, PublicKey d)
        {
            ourPrivate = a;
            ourPublic = b;
            bcPrivate = c;
            bcPublic = d;
        }

        PrivateKey priv(Provider p)
        {
            return p == jsl ? ourPrivate : bcPrivate;
        }

        PublicKey pub(Provider p)
        {
            return p == jsl ? ourPublic : bcPublic;
        }
    }

    private static final Map<String, Keys> KEY_CACHE = new HashMap<String, Keys>();

    /**
     * Generate with JSL, then hand BouncyCastle the ENCODINGS through its own
     * KeyFactory. The sanctioned crossing, and the only one - a key object
     * belongs to the provider instance that made it.
     */
    private static Keys keys(SignatureCell cell) throws Exception
    {
        Keys k = KEY_CACHE.get(cell.keyCacheKey());
        if (k != null)
        {
            return k;
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(cell.kpgAlgorithm, jsl);
        if (cell.kpgSpec != null)
        {
            g.initialize(cell.kpgSpec);
        }
        else if (cell.kpgKeySize > 0)
        {
            g.initialize(cell.kpgKeySize);
        }
        KeyPair kp = g.generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance(cell.bcKeyFactory, bc);
        k = new Keys(kp.getPrivate(), kp.getPublic(),
                kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())),
                kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())));
        KEY_CACHE.put(cell.keyCacheKey(), k);
        return k;
    }

    /**
     * A key of a DIFFERENT family, per provider.
     *
     * <p>Each provider gets its OWN foreign key rather than sharing one object,
     * so the only thing the fault varies is the key's ALGORITHM. Sharing a JSL
     * key with BouncyCastle would additionally vary its provenance, and
     * BouncyCastle's refusal would then be measuring the wrong thing.
     */
    private static Keys foreign(SignatureCell cell) throws Exception
    {
        boolean rsaCell = "RSA".equals(cell.kpgAlgorithm);
        SignatureCell other = rsaCell
                ? new SignatureCell("x", "x", "EC", 0, new ECGenParameterSpec("P-256"), "EC", null, null)
                : new SignatureCell("x", "x", "RSA", 2048, null, "RSA", null, null);
        return keys(other);
    }

    // ------------------------------------------------------------------
    // measurement
    // ------------------------------------------------------------------

    private static Signature sig(Provider p, SignatureCell cell) throws Exception
    {
        Signature s = Signature.getInstance(cell.transformation, p);
        if (cell.params != null)
        {
            s.setParameter(cell.params);
        }
        return s;
    }

    private static byte[] input(SignatureCell cell, byte[] message) throws Exception
    {
        return cell.prehashDigest == null
                ? message
                : MessageDigest.getInstance(cell.prehashDigest).digest(message);
    }

    /** Sign on one provider. */
    private static Observation signWith(Provider p, SignatureCell cell, Keys k, byte[] message)
    {
        return Observer.observe(() -> {
            Signature s = sig(p, cell);
            s.initSign(k.priv(p));
            s.update(input(cell, message));
            return s.sign();
        });
    }

    /** Verify on one provider. */
    private static Observation verifyWith(Provider p, SignatureCell cell, Keys k,
                                          byte[] message, byte[] signature)
    {
        return Observer.observeVerify(() -> {
            Signature v = sig(p, cell);
            v.initVerify(k.pub(p));
            v.update(input(cell, message));
            return v.verify(signature);
        });
    }

    private static Observation applyFault(Provider p, SignatureCell cell, Fault f, Keys k,
                                          byte[] message, byte[] validSig) throws Exception
    {
        Keys other = foreign(cell);
        switch (f)
        {
            case NULL_KEY_VERIFY:
                return Observer.observeVerify(() -> {
                    Signature v = sig(p, cell);
                    v.initVerify((PublicKey) null);
                    v.update(input(cell, message));
                    return v.verify(validSig);
                });
            case WRONG_FAMILY_KEY_VERIFY:
                return Observer.observeVerify(() -> {
                    Signature v = sig(p, cell);
                    v.initVerify(other.pub(p));
                    v.update(input(cell, message));
                    return v.verify(validSig);
                });
            case PRIVATE_KEY_FOR_VERIFY:
                return Observer.observeVerify(() -> {
                    Signature v = sig(p, cell);
                    // Deliberately the raw JCE call a caller would make; the
                    // cast is what makes the SPI see a PrivateKey.
                    v.initVerify((PublicKey) (Object) k.priv(p));
                    v.update(input(cell, message));
                    return v.verify(validSig);
                });
            case UNINITIALISED_VERIFY:
                return Observer.observeVerify(() -> sig(p, cell).verify(validSig));
            case TAMPERED_SIGNATURE:
            {
                byte[] bad = validSig.clone();
                bad[bad.length - 1] ^= (byte) 0x01;
                return verifyWith(p, cell, k, message, bad);
            }
            case TRUNCATED_SIGNATURE:
            {
                byte[] bad = new byte[validSig.length - 1];
                System.arraycopy(validSig, 0, bad, 0, bad.length);
                return verifyWith(p, cell, k, message, bad);
            }
            case GARBAGE_SIGNATURE:
            {
                byte[] bad = new byte[validSig.length];
                SR.nextBytes(bad);
                return verifyWith(p, cell, k, message, bad);
            }
            case EMPTY_SIGNATURE:
                return verifyWith(p, cell, k, message, new byte[0]);
            case TAMPERED_MESSAGE:
            {
                byte[] other2 = message.clone();
                other2[0] ^= (byte) 0x01;
                return verifyWith(p, cell, k, other2, validSig);
            }
            case REUSE_AFTER_SIGN:
                // Verify-shaped ON PURPOSE. The first version signed twice on
                // one instance and compared the SECOND signature's bytes across
                // providers - which reported SILENT_DIVERGENCE for all ten
                // randomised cells (ECDSA, DSA, PSS, ML-DSA, SLH-DSA) and MATCH
                // for the three deterministic PKCS#1 ones. That split is a
                // property of the ALGORITHMS, not of the providers: the fault
                // was measuring randomisation. The property a caller actually
                // depends on is that a terminal sign leaves the instance usable,
                // so measure THAT - the second signature must verify.
                return Observer.observeVerify(() -> {
                    Signature s = sig(p, cell);
                    s.initSign(k.priv(p));
                    s.update(input(cell, message));
                    s.sign();
                    s.update(input(cell, message));
                    byte[] second = s.sign();
                    Signature v = sig(p, cell);
                    v.initVerify(k.pub(p));
                    v.update(input(cell, message));
                    return v.verify(second);
                });
            default:
                break;
        }

        return Observer.observe(() -> {
            Signature s;
            switch (f)
            {
                case NULL_KEY_SIGN:
                    s = sig(p, cell);
                    s.initSign(null);
                    return null;
                case WRONG_FAMILY_KEY_SIGN:
                    s = sig(p, cell);
                    s.initSign(other.priv(p));
                    return null;
                case PUBLIC_KEY_FOR_SIGN:
                    s = sig(p, cell);
                    s.initSign((PrivateKey) (Object) k.pub(p));
                    return null;
                case UNINITIALISED_UPDATE:
                    sig(p, cell).update(input(cell, message));
                    return null;
                case UNINITIALISED_SIGN:
                    return sig(p, cell).sign();
                case FOREIGN_PARAM_SPEC:
                    Signature.getInstance(cell.transformation, p)
                            .setParameter(new PBEParameterSpec(new byte[8], 1000));
                    return null;
                case SET_PARAMETER_AFTER_UPDATE:
                    s = sig(p, cell);
                    s.initSign(k.priv(p));
                    s.update(input(cell, message));
                    s.setParameter(cell.params);
                    return null;
                case SHORT_OUTPUT_BUFFER:
                    s = sig(p, cell);
                    s.initSign(k.priv(p));
                    s.update(input(cell, message));
                    s.sign(new byte[1], 0, 1);
                    return null;
                default:
                    throw new IllegalStateException("unhandled fault " + f);
            }
        });
    }

    /** Which faults make sense for a given cell. */
    static boolean applicable(SignatureCell cell, Fault f)
    {
        switch (f)
        {
            case SET_PARAMETER_AFTER_UPDATE:
                // Only where the cell HAS parameters. Elsewhere setParameter is
                // refused whatever the state, so the cell would measure
                // FOREIGN_PARAM_SPEC a second time under a misleading name.
                return cell.params != null;
            default:
                return true;
        }
    }

    // ------------------------------------------------------------------
    // the survey
    // ------------------------------------------------------------------

    @Test
    public void surveySignatureNegativePaths() throws Exception
    {
        List<String> rows = new ArrayList<String>();
        Map<ParityVerdict, Integer> tally = new EnumMap<ParityVerdict, Integer>(ParityVerdict.class);
        int measured = 0;
        int noBaseline = 0;

        for (SignatureCell cell : cells())
        {
            byte[] message = new byte[64];
            SR.nextBytes(message);

            Keys k;
            try
            {
                k = keys(cell);
            }
            catch (Exception e)
            {
                rows.add(row(cell, "(keygen)", new ParityResult(
                        ParityVerdict.NO_BASELINE, e.getClass().getName(), "-", "key material unavailable")));
                bump(tally, ParityVerdict.NO_BASELINE);
                noBaseline++;
                continue;
            }

            // --- bidirectional baseline -------------------------------
            Observation ourSig = signWith(jsl, cell, k, message);
            Observation bcSig = signWith(bc, cell, k, message);
            ParityResult signBase = ExceptionParity.classify(ourSig, bcSig);
            if (signBase.verdict() == ParityVerdict.BC_ABSENT)
            {
                rows.add(row(cell, "(baseline-sign)", signBase));
                bump(tally, ParityVerdict.BC_ABSENT);
                continue;
            }
            if (!ourSig.hasComparableOutput() || !bcSig.hasComparableOutput())
            {
                rows.add(row(cell, "(baseline-sign)", signBase));
                bump(tally, signBase.verdict());
                noBaseline++;
                continue;
            }

            // Cross-verify BOTH ways. Signature bytes are not compared: ECDSA,
            // DSA, PSS and SLH-DSA are randomised, so byte-equality is not a
            // property either provider promises. Verification is.
            ParityResult cross = ExceptionParity.classify(
                    verifyWith(bc, cell, k, message, ourSig.output()),
                    verifyWith(jsl, cell, k, message, bcSig.output()));
            rows.add(row(cell, "(baseline-crossverify)", cross));
            bump(tally, cross.verdict());
            if (cross.verdict() != ParityVerdict.MATCH_ACCEPT)
            {
                // Either side failing to verify the other's signature means the
                // cell is not comparable; a fault on top measures nothing.
                noBaseline++;
                continue;
            }

            byte[] validSig = ourSig.output();
            for (Fault f : Fault.values())
            {
                if (!applicable(cell, f))
                {
                    continue;
                }
                ParityResult r = ExceptionParity.classify(
                        applyFault(jsl, cell, f, k, message, validSig),
                        applyFault(bc, cell, f, k, message, validSig));
                rows.add(row(cell, f.name(), r));
                bump(tally, r.verdict());
                measured++;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("\n=== MT-31 Signature negative-path survey ===\n");
        for (String r : rows)
        {
            sb.append(r).append('\n');
        }
        sb.append("--- not surveyed, by name ---\n");
        for (Map.Entry<String, String> e : NOT_A_SIGNING_SERVICE.entrySet())
        {
            sb.append(String.format("  %-24s %s%n", e.getKey(), e.getValue()));
        }
        sb.append("--- tally ---\n");
        for (Map.Entry<ParityVerdict, Integer> e : tally.entrySet())
        {
            sb.append(String.format("  %-26s %d%n", e.getKey(), e.getValue()));
        }
        System.out.println(sb);

        // NON-VACUITY ONLY. Not a gate on divergences - see the class note.
        Assertions.assertTrue(measured >= 150,
                "survey measured only " + measured + " fault cells; it is not measuring the surface");
        Assertions.assertTrue(noBaseline * 4 < cells().size(),
                noBaseline + " of " + cells().size() + " cells had no working baseline;"
                        + " the survey is mostly not measuring anything");
    }

    /**
     * The coverage claim, re-derived from the provider rather than from the cell
     * table's length.
     *
     * <p>A differently-shaped second witness for {@link #cells()}: that test
     * measures BEHAVIOUR and can only report on names it was given, so it is
     * structurally blind to a class nobody listed. This one is a static census
     * over {@code getServices()} and can see exactly that. It asserts its own
     * sum, because a census whose prose and tally disagree is the one document
     * that has to be exact.
     */
    @Test
    public void everySignatureSpiClassHasACell()
    {
        Map<String, List<String>> byClass = new TreeMap<String, List<String>>();
        for (Provider.Service sv : jsl.getServices())
        {
            if (!"Signature".equals(sv.getType()))
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
        for (SignatureCell c : cells())
        {
            covered.add(c.spiClass);
        }

        int named = 0;
        StringBuilder sb = new StringBuilder("\n=== Signature SPI-class census ===\n");
        List<String> uncovered = new ArrayList<String>();
        for (Map.Entry<String, List<String>> e : byClass.entrySet())
        {
            named += e.getValue().size();
            boolean ok = covered.contains(e.getKey());
            if (!ok)
            {
                uncovered.add(e.getKey());
            }
            sb.append(String.format("  %-28s %2d names  %s%n",
                    e.getKey(), e.getValue().size(), ok ? "covered" : "NO CELL"));
        }
        sb.append(String.format("  %-28s %2d names across %d classes%n",
                "TOTAL", named, byClass.size()));
        System.out.println(sb);

        // Vacuity: a census that considered nothing must fail, never report clean.
        Assertions.assertTrue(byClass.size() >= 6,
                "census found only " + byClass.size() + " Signature SPI classes; it is not reading the provider");

        // The census asserts its own sum against the provider's own count.
        int direct = 0;
        for (Provider.Service sv : jsl.getServices())
        {
            if ("Signature".equals(sv.getType()))
            {
                direct++;
            }
        }
        Assertions.assertEquals(direct, named,
                "census tally " + named + " does not equal the registered Signature count " + direct);

        Assertions.assertTrue(uncovered.isEmpty(),
                "Signature SPI classes with no survey cell: " + uncovered);

        // A cell naming a class the provider does not register is a stale entry
        // that silently tests nothing - the other direction of the same guard.
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

    private static String row(SignatureCell cell, String fault, ParityResult r)
    {
        String head = String.format("%-22s %-26s %-26s ours=%-34s bc=%-34s %s",
                cell.transformation, fault, r.verdict(),
                simple(r.ourType()), simple(r.bcType()), r.qualifier());
        if (!r.isDivergence())
        {
            return head;
        }
        return head + "\n" + String.format("%-22s %-26s   ours: %s%n%-22s %-26s     bc: %s",
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
