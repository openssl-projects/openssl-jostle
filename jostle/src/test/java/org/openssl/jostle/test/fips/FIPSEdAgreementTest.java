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

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.util.Arrays;

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
 * Cross-provider agreement for the FIPS provider's EdDSA surface.
 * <p>
 * The EdDSA analogue of {@code FIPSRSAAgreementTest} / {@code FIPSECAgreementTest}:
 * every registered Ed transformation is exercised in the same JVM against BOTH
 * the non-FIPS Jostle provider (JSL) AND BouncyCastle (BC), in BOTH directions
 * (JSLFIPS produces and the reference consumes, and vice versa).
 *
 * <p><b>EdDSA is deterministic, so this asserts BYTE-EQUALITY</b> rather than
 * the cross-verify the randomised schemes have to settle for. RSA-PSS and DSA
 * produce a different signature every time, so their agreement tests can only
 * check that each side accepts the other's output; here all three providers
 * must emit the <i>identical</i> bytes over the same key and message. That is a
 * strictly stronger property — an implementation that produced a valid but
 * different signature would pass a cross-verify and fail here.
 *
 * <p><b>Key isolation.</b> A Jostle key belongs to the provider INSTANCE that
 * created it, and since MT-14 neither half crosses as an object
 * ({@code FIPSKeyIsolationTest} owns that contract). To run the SAME key
 * material through all three providers, this test generates one keypair in the
 * module, encodes both halves (X.509 / PKCS#8), and decodes them through each
 * provider's own KeyFactory — the sanctioned crossing, and the only one.
 *
 * <p><b>The prehash variants have no BC JCE name</b> ({@code Signature.Ed25519ph}
 * is absent; only {@code Ed25519} / {@code Ed448} / {@code EdDSA} are
 * registered). Per the interop-reference order in the migration plan, a missing
 * BC JCE name is not a reason to skip agreement testing — the reference is then
 * BC's LIGHTWEIGHT API, {@code Ed25519phSigner} / {@code Ed448phSigner}, driven
 * directly from the test. Without this, ED25519PH and ED448PH would be
 * registered with no agreement coverage at all.
 *
 * <p>Gated on {@code TEST_FIPS_LIB} and on the loaded module serving the family
 * (3.1.2 refuses it, 3.5.7 serves it — see
 * {@code FIPSEdSignatureTest.edServedIffModuleImplementsIt}, which runs on both
 * and pins the absence against the module itself).
 */
public class FIPSEdAgreementTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** Trials per randomised agreement test. */
    private static final int TRIALS = 12;

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static void assumeEdServed()
    {
        Assumptions.assumeTrue(
                Security.getProvider(FIPS).getService("KeyPairGenerator", "ED25519") != null,
                "the loaded FIPS module does not implement Ed25519/Ed448");
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    /**
     * The pure forms, all three providers, both directions.
     * <p>
     * BC's JCE surface registers {@code Ed25519} / {@code Ed448}, so it is the
     * reference here (the plan's interop order prefers the JCE surface where it
     * exists).
     */
    @Test
    public void pureSignaturesAgreeWithJslAndBc()
        throws Exception
    {
        assumeEdServed();
        SecureRandom sr = seededRandom("pureSignaturesAgreeWithJslAndBc");

        for (String alg : new String[]{"ED25519", "ED448"})
        {
            String bcName = "ED25519".equals(alg) ? "Ed25519" : "Ed448";

            for (int trial = 0; trial < TRIALS; trial++)
            {
                KeyPair kp = KeyPairGenerator.getInstance(alg, FIPS).generateKeyPair();
                byte[] spki = kp.getPublic().getEncoded();
                byte[] pkcs8 = kp.getPrivate().getEncoded();

                byte[] msg = new byte[1 + sr.nextInt(2048)];
                sr.nextBytes(msg);

                byte[] fipsSig = sign(alg, FIPS, kp.getPrivate(), msg);

                // --- JSLFIPS vs JSL, same key material -----------------------
                PrivateKey jslPriv = privateVia(alg, JSL, pkcs8);
                PublicKey jslPub = publicVia(alg, JSL, spki);
                Assertions.assertTrue(Arrays.areEqual(fipsSig, sign(alg, JSL, jslPriv, msg)),
                        alg + ": JSLFIPS and JSL produced different signatures");
                Assertions.assertTrue(verify(alg, JSL, jslPub, msg, fipsSig),
                        alg + ": JSL rejected a JSLFIPS signature");
                Assertions.assertTrue(
                        verify(alg, FIPS, kp.getPublic(), msg, sign(alg, JSL, jslPriv, msg)),
                        alg + ": JSLFIPS rejected a JSL signature");

                // --- JSLFIPS vs BC, same key material ------------------------
                PrivateKey bcPriv = privateVia("EdDSA", BC, pkcs8);
                PublicKey bcPub = publicVia("EdDSA", BC, spki);
                Assertions.assertTrue(Arrays.areEqual(fipsSig, sign(bcName, BC, bcPriv, msg)),
                        alg + ": JSLFIPS and BC produced different signatures");
                Assertions.assertTrue(verify(bcName, BC, bcPub, msg, fipsSig),
                        alg + ": BC rejected a JSLFIPS signature");
                Assertions.assertTrue(
                        verify(alg, FIPS, kp.getPublic(), msg, sign(bcName, BC, bcPriv, msg)),
                        alg + ": JSLFIPS rejected a BC signature");
            }
        }
    }

    /**
     * The prehash forms, all three providers, both directions.
     * <p>
     * JSL is reached through its JCE {@code ED25519PH} / {@code ED448PH}
     * registration; BC only through the lightweight
     * {@code Ed25519phSigner} / {@code Ed448phSigner}, since it registers no
     * JCE name for them.
     */
    @Test
    public void prehashSignaturesAgreeWithJslAndBcLightweight()
        throws Exception
    {
        assumeEdServed();
        SecureRandom sr = seededRandom("prehashSignaturesAgreeWithJslAndBcLightweight");

        for (String phAlg : new String[]{"ED25519PH", "ED448PH"})
        {
            Assumptions.assumeTrue(
                    Security.getProvider(FIPS).getService("Signature", phAlg) != null,
                    "the loaded FIPS module does not serve " + phAlg);

            String kpgAlg = phAlg.startsWith("ED25519") ? "ED25519" : "ED448";

            for (int trial = 0; trial < TRIALS; trial++)
            {
                KeyPair kp = KeyPairGenerator.getInstance(kpgAlg, FIPS).generateKeyPair();
                byte[] spki = kp.getPublic().getEncoded();
                byte[] pkcs8 = kp.getPrivate().getEncoded();

                byte[] msg = new byte[1 + sr.nextInt(2048)];
                sr.nextBytes(msg);

                byte[] fipsSig = sign(phAlg, FIPS, kp.getPrivate(), msg);

                // --- JSLFIPS vs JSL ------------------------------------------
                PrivateKey jslPriv = privateVia(kpgAlg, JSL, pkcs8);
                PublicKey jslPub = publicVia(kpgAlg, JSL, spki);
                Assertions.assertTrue(Arrays.areEqual(fipsSig, sign(phAlg, JSL, jslPriv, msg)),
                        phAlg + ": JSLFIPS and JSL produced different signatures");
                Assertions.assertTrue(verify(phAlg, JSL, jslPub, msg, fipsSig),
                        phAlg + ": JSL rejected a JSLFIPS signature");

                // --- JSLFIPS vs BC lightweight, empty context ----------------
                byte[] bcSig = bcPrehashSign(phAlg, pkcs8, new byte[0], msg);
                Assertions.assertTrue(Arrays.areEqual(fipsSig, bcSig),
                        phAlg + ": JSLFIPS and BC's lightweight signer produced different signatures");
                Assertions.assertTrue(bcPrehashVerify(phAlg, spki, new byte[0], msg, fipsSig),
                        phAlg + ": BC's lightweight signer rejected a JSLFIPS signature");
                Assertions.assertTrue(verify(phAlg, FIPS, kp.getPublic(), msg, bcSig),
                        phAlg + ": JSLFIPS rejected a BC lightweight signature");
            }
        }
    }

    /**
     * The prehash forms carrying a non-empty RFC 8032 context string.
     * <p>
     * Two properties, and the second is what makes the first meaningful: the
     * context must be honoured <i>identically</i> by JSLFIPS and BC, and a
     * DIFFERENT context must produce a DIFFERENT signature. Without the
     * differentiator an implementation that silently ignored the context would
     * still agree with a reference that also ignored it.
     */
    @Test
    public void prehashContextIsHonouredAndAgreesWithBc()
        throws Exception
    {
        assumeEdServed();
        SecureRandom sr = seededRandom("prehashContextIsHonouredAndAgreesWithBc");

        for (String phAlg : new String[]{"ED25519PH", "ED448PH"})
        {
            Assumptions.assumeTrue(
                    Security.getProvider(FIPS).getService("Signature", phAlg) != null,
                    "the loaded FIPS module does not serve " + phAlg);

            String kpgAlg = phAlg.startsWith("ED25519") ? "ED25519" : "ED448";
            KeyPair kp = KeyPairGenerator.getInstance(kpgAlg, FIPS).generateKeyPair();
            byte[] spki = kp.getPublic().getEncoded();
            byte[] pkcs8 = kp.getPrivate().getEncoded();

            for (int trial = 0; trial < TRIALS; trial++)
            {
                byte[] msg = new byte[1 + sr.nextInt(512)];
                sr.nextBytes(msg);
                // RFC 8032 caps the context at 255 bytes.
                byte[] context = new byte[1 + sr.nextInt(32)];
                sr.nextBytes(context);

                byte[] fipsSig = signWithContext(phAlg, kp.getPrivate(), context, msg);

                Assertions.assertTrue(
                        Arrays.areEqual(fipsSig, bcPrehashSign(phAlg, pkcs8, context, msg)),
                        phAlg + ": JSLFIPS and BC disagree once a context string is supplied");
                Assertions.assertTrue(bcPrehashVerify(phAlg, spki, context, msg, fipsSig),
                        phAlg + ": BC rejected a JSLFIPS signature made with a context");

                // Differentiator: a different context MUST change the signature.
                byte[] other = Arrays.clone(context);
                other[sr.nextInt(other.length)] ^= (byte) 0x01;
                Assertions.assertFalse(
                        Arrays.areEqual(fipsSig, signWithContext(phAlg, kp.getPrivate(), other, msg)),
                        phAlg + ": a different context produced the same signature — the context "
                                + "is being ignored");

                // And the empty-context signature must differ from both.
                Assertions.assertFalse(
                        Arrays.areEqual(fipsSig, sign(phAlg, FIPS, kp.getPrivate(), msg)),
                        phAlg + ": supplying a context made no difference to the signature");
            }
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static PrivateKey privateVia(String kfAlg, String provider, byte[] pkcs8)
        throws Exception
    {
        return KeyFactory.getInstance(kfAlg, provider).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    private static PublicKey publicVia(String kfAlg, String provider, byte[] spki)
        throws Exception
    {
        return KeyFactory.getInstance(kfAlg, provider).generatePublic(new X509EncodedKeySpec(spki));
    }

    private static byte[] sign(String alg, String provider, PrivateKey key, byte[] msg)
        throws Exception
    {
        Signature s = Signature.getInstance(alg, provider);
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    private static byte[] signWithContext(String alg, PrivateKey key, byte[] context, byte[] msg)
        throws Exception
    {
        Signature s = Signature.getInstance(alg, FIPS);
        // setParameter must precede init - the SPI reads the spec when it binds
        // the key, and rejects a spec supplied mid-update.
        s.setParameter(new ContextParameterSpec(context));
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

    /** BC's lightweight prehash signer, built from the encoded private key. */
    private static byte[] bcPrehashSign(String phAlg, byte[] pkcs8, byte[] context, byte[] msg)
        throws Exception
    {
        AsymmetricKeyParameter priv = PrivateKeyFactory.createKey(pkcs8);
        Signer signer = bcPrehashSigner(phAlg, context);
        signer.init(true, priv);
        signer.update(msg, 0, msg.length);
        return signer.generateSignature();
    }

    /** BC's lightweight prehash verifier, built from the encoded public key. */
    private static boolean bcPrehashVerify(String phAlg, byte[] spki, byte[] context,
                                           byte[] msg, byte[] sig)
        throws Exception
    {
        AsymmetricKeyParameter pub = PublicKeyFactory.createKey(spki);
        Signer verifier = bcPrehashSigner(phAlg, context);
        verifier.init(false, pub);
        verifier.update(msg, 0, msg.length);
        return verifier.verifySignature(sig);
    }

    private static Signer bcPrehashSigner(String phAlg, byte[] context)
    {
        if (phAlg.startsWith("ED25519"))
        {
            return new Ed25519phSigner(context);
        }
        return new Ed448phSigner(context);
    }

    /**
     * Runs on EVERY module, and exists so this class never skips wholesale.
     * <p>
     * The three agreement tests below genuinely cannot run without the module
     * implementing Ed — there is nothing to agree about — so each takes
     * {@link #assumeEdServed()}. Against 3.1.2 that left the entire class
     * skipped, which {@code verify-results.py --require-fips} rejects, and
     * rightly: a class that skips in full is indistinguishable from one
     * silently dropped, and the "absence" it leaves behind is asserted by
     * nobody.
     * <p>
     * So the class keeps one test that is meaningful on both modules: the
     * registration must track what the module actually implements, in BOTH
     * directions. Served-but-unimplemented would mean {@code getInstance}
     * resolves and every {@code init} fails; implemented-but-unserved would
     * mean a working algorithm was dropped from callers. Same shape as
     * {@code FIPSEdSignatureTest.edServedIffModuleImplementsIt}, and the
     * reason that class does not skip wholesale either.
     */
    @Test
    public void edAgreementIsAvailableIffTheModuleImplementsIt()
    {
        boolean served = Security.getProvider(FIPS)
                .getService("KeyPairGenerator", "ED25519") != null;
        boolean implemented = FIPSNISelector.OpenSSLFIPSNI
                .canFetch(OpenSSLFIPSNI.OP_KEYMGMT, "ED25519") != 0;

        Assertions.assertEquals(implemented, served,
                served
                        ? "JSLFIPS registers Ed25519 but the loaded module does not implement it — "
                          + "getInstance would resolve and every init would fail"
                        : "the loaded module implements Ed25519 but JSLFIPS does not register it — "
                          + "a working algorithm was dropped from callers");

        // A control, so the probe cannot pass by answering the same thing to
        // everything: the module must resolve a digest it certainly has, and
        // must NOT resolve an algorithm no FIPS module carries.
        Assertions.assertTrue(
                FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_MD, "SHA-256") != 0,
                "the capability probe cannot see the module at all");
        Assertions.assertEquals(0,
                FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_CIPHER, "ChaCha20"),
                "the capability probe answers yes to everything, so it proves nothing");
    }
}
