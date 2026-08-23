/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * EdDSA (Ed25519 / Ed448) through the FIPS provider ("JSLFIPS"): the
 * registration contract against the loaded module, the negative paths,
 * chunking, reset/reuse, and encoding round-trips.
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 *
 * <p>Cross-provider AGREEMENT lives next door in {@code FIPSEdAgreementTest},
 * following the house {@code FIPS<X>AgreementTest} convention: JSLFIPS against
 * both JSL and BouncyCastle, both directions, including the prehash variants
 * (which need BC's lightweight signer — BC registers no JCE name for them).
 *
 * <p>The family is <b>capability-gated</b> — 3.1.2 refuses it outright, 3.5.7
 * serves it — so every operational test here first takes the
 * {@link #assumeEdServed()} skip. {@link #edServedIffModuleImplementsIt} is
 * the one test that runs on both modules and pins the contract itself; the
 * skips below it are legitimate only because that test asserts the absence is
 * the module's and not a Jostle regression.
 */
public class FIPSEdSignatureTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Trials per randomised agreement test. */
    private static final int TRIALS = 12;

    /** Signature names whose OpenSSL instance is a PURE (non-prehash) form. */
    private static final String[] PURE = {"ED25519", "ED448"};

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * A reproducible RNG whose seed is printed, so a failing random trial can
     * be replayed (the project pattern from {@code EdDSATest}).
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static boolean resolves(String type, String algorithm)
    {
        return Security.getProvider(JostleFIPSProvider.PROVIDER_NAME)
                .getService(type, algorithm) != null;
    }

    /** Does JSLFIPS carry the Ed family at all? */
    private static boolean edIsRegistered()
    {
        return resolves("KeyPairGenerator", "ED25519");
    }

    private static void assumeEdServed()
    {
        Assumptions.assumeTrue(edIsRegistered(),
                "the loaded FIPS module does not implement Ed25519/Ed448");
    }

    /**
     * EdDSA is served by JSLFIPS <b>if and only if</b> the loaded module
     * implements it — asserted as a contract, because the two supported
     * modules disagree and neither answer may be hard-coded:
     *
     * <pre>
     *   3.1.2 : keymgmt and every EVP_SIGNATURE name refused -> nothing registered
     *   3.5.7 : keymgmt ok; ED25519 / ED25519PH / ED448 / ED448PH registered,
     *           ED25519CTX NOT (the module does not register that instance)
     * </pre>
     *
     * Measured by {@code fips-c-review/probes/ed_gate_probe.c}, identically
     * under the default and the {@code -pedantic} fipsinstall config.
     *
     * <p>Both halves are load-bearing. Where the module serves Ed, refusing to
     * register would remove a working algorithm from callers. Where it does
     * not, registering would hand back a service that fails at first use
     * instead of a clean {@code NoSuchAlgorithmException} the caller can fall
     * through from.
     *
     * <p>The all-or-nothing assertion over the family is what a single-service
     * check would miss — <b>except</b> for ED25519CTX, which is deliberately
     * excluded from that sweep and checked against its own signature-level
     * probe. Asserting it were simply absent would be wrong: it would pass
     * unchanged if a later module started serving it, leaving callers refused
     * for a reason that no longer holds.
     */
    @Test
    public void edServedIffModuleImplementsIt()
        throws Exception
    {
        boolean served = edIsRegistered();

        // Ask the MODULE, not just ourselves. Without this the test derives
        // "served" from the registration and then checks the registration
        // against itself — so dropping the whole family on a module that
        // implements it would pass. (The snapshot test catches that too; this
        // keeps the contract legible in one place.)
        Assertions.assertEquals(FIPSTestUtil.moduleServesSignature("ED25519"), served,
                "the Ed family's registration disagrees with the loaded module");

        for (String alg : new String[]{"ED25519", "ED448"})
        {
            Assertions.assertEquals(served, resolves("KeyFactory", alg),
                    "KeyFactory." + alg + " registration disagrees with the rest of the Ed family");
            Assertions.assertEquals(served, resolves("KeyPairGenerator", alg),
                    "KeyPairGenerator." + alg + " registration disagrees with the rest of the Ed family");
        }
        for (String alg : new String[]{"ED", "EDDSA"})
        {
            Assertions.assertEquals(served, resolves("KeyFactory", alg),
                    "KeyFactory." + alg + " registration disagrees with the rest of the Ed family");
        }
        for (String alg : new String[]{"ED25519", "ED25519PH", "ED448", "ED448PH", "EDDSA"})
        {
            Assertions.assertEquals(served, resolves("Signature", alg),
                    "Signature." + alg + " registration disagrees with the rest of the Ed family");
        }

        // ED25519CTX tracks its OWN capability, not the family's: on 3.5.7 the
        // family is served and this instance is not.
        Assertions.assertEquals(
                FIPSTestUtil.moduleServesSignature("ED25519CTX"),
                resolves("Signature", "ED25519CTX"),
                "Signature.ED25519CTX registration disagrees with the module's own "
                        + "EVP_SIGNATURE_fetch answer");

        if (!served)
        {
            // The module genuinely cannot do it — JSL, on mainline libcrypto,
            // still can. Proves the absence is this module's limit and not a
            // Jostle-wide regression.
            Assertions.assertNotNull(
                    KeyPairGenerator.getInstance("ED25519", JostleProvider.PROVIDER_NAME),
                    "ED25519 must still resolve through JSL");
            return;
        }

        // Registration is not usability: every registered name must actually
        // sign and verify.
        for (String alg : new String[]{"ED25519", "ED25519PH", "ED448", "ED448PH"})
        {
            if (!resolves("Signature", alg))
            {
                continue;
            }
            String kpgAlg = alg.startsWith("ED25519") ? "ED25519" : "ED448";
            KeyPair kp = KeyPairGenerator.getInstance(kpgAlg, JostleFIPSProvider.PROVIDER_NAME)
                    .generateKeyPair();
            byte[] msg = new byte[97];
            RANDOM.nextBytes(msg);
            byte[] sig = sign(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPrivate(), msg);
            Assertions.assertTrue(verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), msg, sig),
                    alg + " is registered but cannot verify its own signature");
        }
    }

    /**
     * The negative paths: a tampered message, a tampered signature and a
     * wrong public key must all fail verification.
     *
     * <p>Without these the round-trip above would pass against a
     * {@code verify()} stubbed to return true.
     */
    @Test
    public void negativePaths()
        throws Exception
    {
        assumeEdServed();
        SecureRandom sr = seededRandom("negativePaths");

        for (String alg : PURE)
        {
            for (int trial = 0; trial < TRIALS; trial++)
            {
                KeyPair kp = KeyPairGenerator.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME)
                        .generateKeyPair();
                KeyPair other = KeyPairGenerator.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME)
                        .generateKeyPair();

                byte[] msg = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(msg);
                byte[] sig = sign(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPrivate(), msg);

                Assertions.assertTrue(
                        verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), msg, sig),
                        alg + ": the untampered control must verify");

                byte[] badMsg = Arrays.clone(msg);
                badMsg[sr.nextInt(badMsg.length)] ^= (byte) (1 << sr.nextInt(8));
                Assertions.assertFalse(
                        verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), badMsg, sig),
                        alg + ": a tampered message verified");

                byte[] badSig = Arrays.clone(sig);
                badSig[sr.nextInt(badSig.length)] ^= (byte) (1 << sr.nextInt(8));
                Assertions.assertFalse(
                        verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), msg, badSig),
                        alg + ": a tampered signature verified");

                Assertions.assertFalse(
                        verify(alg, JostleFIPSProvider.PROVIDER_NAME, other.getPublic(), msg, sig),
                        alg + ": a foreign public key verified the signature");

                // Distinct messages must produce distinct signatures — catches
                // an implementation that ignores its input.
                byte[] msg2 = new byte[msg.length];
                sr.nextBytes(msg2);
                if (!Arrays.areEqual(msg, msg2))
                {
                    Assertions.assertFalse(
                            Arrays.areEqual(sig, sign(alg, JostleFIPSProvider.PROVIDER_NAME,
                                    kp.getPrivate(), msg2)),
                            alg + ": two different messages produced the same signature");
                }
            }
        }
    }

    /**
     * The chunking matrix: one-shot, byte-by-byte and random splits over the
     * same message must produce the identical signature, and each must verify.
     * A buffering bug in the streaming path is invisible to a one-shot-only
     * test.
     */
    @Test
    public void chunkingMatrixAgrees()
        throws Exception
    {
        assumeEdServed();
        SecureRandom sr = seededRandom("chunkingMatrixAgrees");

        for (String alg : PURE)
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME)
                    .generateKeyPair();
            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] msg = new byte[1 + sr.nextInt(1024)];
                sr.nextBytes(msg);
                byte[] reference = sign(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPrivate(), msg);

                // byte at a time
                Signature s = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
                s.initSign(kp.getPrivate());
                for (byte b : msg)
                {
                    s.update(b);
                }
                Assertions.assertTrue(Arrays.areEqual(reference, s.sign()),
                        alg + ": byte-at-a-time signing diverged from one-shot");

                // random splits
                s = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
                s.initSign(kp.getPrivate());
                int off = 0;
                while (off < msg.length)
                {
                    int len = 1 + sr.nextInt(msg.length - off);
                    s.update(msg, off, len);
                    off += len;
                }
                byte[] split = s.sign();
                Assertions.assertTrue(Arrays.areEqual(reference, split),
                        alg + ": randomly-split signing diverged from one-shot");
                Assertions.assertTrue(
                        verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), msg, split),
                        alg + ": randomly-split signature did not verify");
            }
        }
    }

    /**
     * Reset / reuse, the six patterns from the test-discipline checklist that
     * apply to a deterministic Signature: two distinct inputs through one
     * instance, the same input twice (must be byte-EQUAL — EdDSA is
     * deterministic), negative-then-positive, positive-then-negative, and the
     * sign/verify role flip.
     */
    @Test
    public void resetAndReuse()
        throws Exception
    {
        assumeEdServed();
        SecureRandom sr = seededRandom("resetAndReuse");

        for (String alg : PURE)
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME)
                    .generateKeyPair();
            byte[] a = new byte[64];
            byte[] b = new byte[97];
            sr.nextBytes(a);
            sr.nextBytes(b);

            // 1. two distinct inputs through ONE instance
            Signature s = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            s.initSign(kp.getPrivate());
            s.update(a);
            byte[] sigA = s.sign();
            s.update(b);
            byte[] sigB = s.sign();
            Assertions.assertFalse(Arrays.areEqual(sigA, sigB),
                    alg + ": two different messages through one instance signed identically");
            Assertions.assertTrue(verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), a, sigA),
                    alg + ": first signature of a reused instance is wrong");
            Assertions.assertTrue(verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), b, sigB),
                    alg + ": second signature of a reused instance is wrong");

            // 2. same input twice — DETERMINISTIC, so byte-equal
            s.update(a);
            byte[] sigA2 = s.sign();
            Assertions.assertTrue(Arrays.areEqual(sigA, sigA2),
                    alg + ": EdDSA is deterministic but a repeated signature differed");

            // 3. negative then positive: a failed verify must not poison state
            Signature v = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            v.initVerify(kp.getPublic());
            v.update(b);
            Assertions.assertFalse(v.verify(sigA), alg + ": wrong message verified");
            v.update(a);
            Assertions.assertTrue(v.verify(sigA),
                    alg + ": a successful verify after a failed one did not work — state was poisoned");

            // 4. positive then negative on the same instance
            v.update(a);
            Assertions.assertTrue(v.verify(sigA), alg + ": positive control failed");
            v.update(b);
            Assertions.assertFalse(v.verify(sigA),
                    alg + ": a failing verify after a successful one returned true — a cached result");

            // 5. role flip on one instance: sign -> verify -> sign
            Signature flip = Signature.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);
            flip.initSign(kp.getPrivate());
            flip.update(a);
            byte[] flipSig = flip.sign();
            flip.initVerify(kp.getPublic());
            flip.update(a);
            Assertions.assertTrue(flip.verify(flipSig), alg + ": verify after sign on one instance failed");
            flip.initSign(kp.getPrivate());
            flip.update(b);
            Assertions.assertTrue(
                    verify(alg, JostleFIPSProvider.PROVIDER_NAME, kp.getPublic(), b, flip.sign()),
                    alg + ": sign after verify on one instance produced a bad signature");
        }
    }

    /**
     * Key encodings round-trip through BouncyCastle in both directions, for
     * both halves of the pair — and the re-encoded form is byte-identical, so
     * a key that merely "works" while carrying a different AlgorithmIdentifier
     * cannot pass (the PSS-OID lesson).
     */
    @Test
    public void keyEncodingsRoundTripThroughBC()
        throws Exception
    {
        assumeEdServed();

        for (String alg : PURE)
        {
            KeyFactory bcKf = KeyFactory.getInstance("EdDSA", BouncyCastleProvider.PROVIDER_NAME);
            KeyFactory fipsKf = KeyFactory.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME);

            // JSLFIPS -> BC -> JSLFIPS
            KeyPair kp = KeyPairGenerator.getInstance(alg, JostleFIPSProvider.PROVIDER_NAME)
                    .generateKeyPair();
            byte[] spki = kp.getPublic().getEncoded();
            byte[] pkcs8 = kp.getPrivate().getEncoded();

            PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(spki));
            PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            Assertions.assertTrue(Arrays.areEqual(spki, bcPub.getEncoded()),
                    alg + ": BC re-encoded the public key differently");
            Assertions.assertTrue(Arrays.areEqual(pkcs8, bcPriv.getEncoded()),
                    alg + ": BC re-encoded the private key differently");

            Assertions.assertTrue(Arrays.areEqual(spki,
                            fipsKf.generatePublic(new X509EncodedKeySpec(bcPub.getEncoded())).getEncoded()),
                    alg + ": public key did not survive the JSLFIPS -> BC -> JSLFIPS round trip");
            Assertions.assertTrue(Arrays.areEqual(pkcs8,
                            fipsKf.generatePrivate(new PKCS8EncodedKeySpec(bcPriv.getEncoded())).getEncoded()),
                    alg + ": private key did not survive the JSLFIPS -> BC -> JSLFIPS round trip");

            // BC -> JSLFIPS -> BC
            KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EdDSA",
                    BouncyCastleProvider.PROVIDER_NAME);
            bcKpg.initialize(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec(
                    "ED25519".equals(alg) ? "Ed25519" : "Ed448"));
            KeyPair bcKp = bcKpg.generateKeyPair();
            byte[] bcSpki = bcKp.getPublic().getEncoded();
            byte[] bcPkcs8 = bcKp.getPrivate().getEncoded();

            Assertions.assertTrue(Arrays.areEqual(bcSpki,
                            fipsKf.generatePublic(new X509EncodedKeySpec(bcSpki)).getEncoded()),
                    alg + ": JSLFIPS re-encoded a BC public key differently");

            // The private half is NOT byte-comparable in this direction, and
            // that is correct rather than a defect: RFC 8410 §7 makes the
            // public key an OPTIONAL field of the OneAsymmetricKey, so BC
            // emits PKCS#8 v1 carrying it (83 bytes for Ed25519) while Jostle
            // emits v0 without it (48 bytes). Both decode to the same private
            // scalar; BC accepts Jostle's v0 form and re-encodes it
            // byte-identically, which the JSLFIPS -> BC -> JSLFIPS leg above
            // already pins. Do not "fix" this by making one side match the
            // other — assert the properties a caller depends on instead.
            PrivateKey crossed = fipsKf.generatePrivate(new PKCS8EncodedKeySpec(bcPkcs8));

            // 1. the algorithm identifier survives: the public key JSLFIPS
            //    derives from the imported private key re-encodes to exactly
            //    BC's SPKI, OID and all.
            byte[] derivedSpki = fipsKf.generatePublic(new X509EncodedKeySpec(bcSpki)).getEncoded();
            Assertions.assertTrue(Arrays.areEqual(bcSpki, derivedSpki),
                    alg + ": the imported key's AlgorithmIdentifier changed");

            // 2. the key material survives: EdDSA is deterministic, so the
            //    imported key must sign to BC's exact signature.
            byte[] msg = new byte[128];
            RANDOM.nextBytes(msg);
            Assertions.assertTrue(Arrays.areEqual(
                            sign("EdDSA", BouncyCastleProvider.PROVIDER_NAME, bcKp.getPrivate(), msg),
                            sign(alg, JostleFIPSProvider.PROVIDER_NAME, crossed, msg)),
                    alg + ": the imported private key signed differently from BC's original");

            // 3. JSLFIPS's own encoding is stable: re-decoding what it emitted
            //    reproduces it exactly, so the v0 form is a fixed point and
            //    not a lossy step in a longer chain.
            byte[] jslForm = crossed.getEncoded();
            Assertions.assertTrue(Arrays.areEqual(jslForm,
                            fipsKf.generatePrivate(new PKCS8EncodedKeySpec(jslForm)).getEncoded()),
                    alg + ": JSLFIPS's own private-key encoding is not a fixed point");
            Assertions.assertTrue(Arrays.areEqual(jslForm,
                            bcKf.generatePrivate(new PKCS8EncodedKeySpec(jslForm)).getEncoded()),
                    alg + ": BC did not re-encode JSLFIPS's private key byte-identically");
        }
    }

    /**
     * The wrong-key-type rejection, which is a different check from the
     * cross-provider isolation {@code FIPSKeyIsolationTest} owns: an Ed448 key
     * handed to an Ed25519 Signature must be refused typed.
     */
    @Test
    public void wrongKeyTypeRejectedTyped()
        throws Exception
    {
        assumeEdServed();

        KeyPair ed448 = KeyPairGenerator.getInstance("ED448", JostleFIPSProvider.PROVIDER_NAME)
                .generateKeyPair();
        Signature s = Signature.getInstance("ED25519", JostleFIPSProvider.PROVIDER_NAME);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> s.initSign(ed448.getPrivate()));
        Assertions.assertTrue(e.getMessage().startsWith("required ED25519 key type but got "),
                "unexpected message: " + e.getMessage());

        KeyPair ed25519 = KeyPairGenerator.getInstance("ED25519", JostleFIPSProvider.PROVIDER_NAME)
                .generateKeyPair();
        Signature s2 = Signature.getInstance("ED448", JostleFIPSProvider.PROVIDER_NAME);
        InvalidKeyException e2 = Assertions.assertThrows(InvalidKeyException.class,
                () -> s2.initVerify(ed25519.getPublic()));
        Assertions.assertTrue(e2.getMessage().startsWith("required ED448 key type but got "),
                "unexpected message: " + e2.getMessage());
    }

    private static byte[] sign(String alg, String provider, PrivateKey key, byte[] msg)
        throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(String alg, String provider, PublicKey key, byte[] msg, byte[] sig)
        throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }
}
