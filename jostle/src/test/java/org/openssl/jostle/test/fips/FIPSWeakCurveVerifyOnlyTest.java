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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

import javax.crypto.KeyAgreement;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * The below-112-bit curves are VERIFY-ONLY under JSLFIPS, on both supported
 * modules: a legacy signature still verifies, and nothing new can be signed or
 * agreed. Refusing them at mint would turn away that one legitimate use — the
 * over-refusal the ruling in the batch note rejected.
 *
 * <p>Only MINTING differs between the modules (3.1.2 mints, 3.5.8 refuses), so
 * every cell but one is unconditional. That one branches on the mint call's own
 * outcome: {@code OpenSSLFIPSNI.moduleVersion} is diagnostics-only by contract,
 * and a {@code TEST_FIPS_LIB} path is a label rather than a measurement.
 *
 * <p>OpenSSL's refusal text differs by module, so none of it is pinned. What is
 * pinned is our own prefix plus the cause, asserted by concatenation.
 *
 * <p>{@code FIPSEcCofactorEcdhTest} pins WHERE the same refusal lands; this
 * file pins WHAT still works.
 */
public class FIPSWeakCurveVerifyOnlyTest
{
    /** Below 112-bit security. Verify-only on every supported module. */
    private static final String[] WEAK_CURVES = {"secp192r1", "sect163k1", "sect163r2"};

    /** Strong, cofactor 1: everything must work, on whichever module is loaded. */
    private static final String CONTROL_CURVE = "secp256r1";

    /** The prefix {@code ECDHKeyAgreementSpi.engineInit} puts before the provider's text. */
    private static final String ECDH_INIT_PREFIX =
            "ECDH init: the provider refused this private key: ";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static Provider fips;
    private static Provider jsl;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /**
     * THE LOAD-BEARING ARM. A signature made elsewhere on a weak curve still
     * verifies under JSLFIPS. This is what makes refusing at mint wrong, so it
     * must not be dropped or weakened.
     *
     * <p>JSL signs because the module will not: the signature has to come from
     * outside, which is also what a caller checking a legacy signature has.
     */
    @Test
    public void weakCurvesStillVerifyASignatureMadeElsewhere() throws Exception
    {
        for (String curve : WEAK_CURVES)
        {
            byte[] msg = randomMessage();
            KeyPair signer = generate(jsl, curve);
            byte[] sig = sign(jsl, signer.getPrivate(), msg);

            PublicKey pub = FIPSTestUtil.crossPublic(signer.getPublic(), "EC", fips.getName());

            Assertions.assertTrue(verify(fips, pub, msg, sig),
                    curve + ": the module must still verify a signature made elsewhere");

            // A verify stubbed to return true passes the line above. Tamper the
            // message and require it to say no.
            byte[] tampered = org.openssl.jostle.util.Arrays.clone(msg);
            tampered[0] ^= (byte) 0x01;
            Assertions.assertFalse(verify(fips, pub, tampered, sig),
                    curve + ": a tampered message must not verify");
        }
    }

    /**
     * Sign and derive are refused with the JCE-canonical init type, and the
     * message carries the provider's own text rather than naming a cause we
     * guessed. Unconditional: the key is IMPORTED, so this holds on the module
     * that cannot mint it either.
     */
    @Test
    public void weakCurvesRefuseSignAndDeriveWithTheCanonicalType() throws Exception
    {
        for (String curve : WEAK_CURVES)
        {
            KeyPair minted = generate(jsl, curve);
            KeyPair peer = generate(jsl, curve);
            PrivateKey priv = FIPSTestUtil.crossPrivate(minted.getPrivate(), "EC", fips.getName());
            PublicKey peerPub = FIPSTestUtil.crossPublic(peer.getPublic(), "EC", fips.getName());

            assertRefusedAtSign(curve, priv);
            assertRefusedAtDerive(curve, priv, peerPub);
        }
    }

    /**
     * The single module-dependent fact. 3.1.2 mints these curves; 3.5.8 refuses
     * at mint. Branched on what the operation itself answered, and each answer
     * pins exactly one shape — neither arm can pass vacuously.
     *
     * <p>A minted key must behave exactly like an imported one, or minting has
     * produced something with powers the import does not have.
     */
    @Test
    public void weakCurveMintEitherSucceedsAndStaysVerifyOnlyOrRefusesTyped() throws Exception
    {
        for (String curve : WEAK_CURVES)
        {
            KeyPair minted;
            try
            {
                minted = generate(fips, curve);
            }
            catch (InvalidAlgorithmParameterException refusedAtMint)
            {
                Assertions.assertEquals(InvalidAlgorithmParameterException.class,
                        refusedAtMint.getClass(),
                        curve + ": a mint refusal must be the canonical type exactly");
                Assertions.assertEquals(
                        "curve '" + curve + "' is not supported by the loaded OpenSSL build",
                        refusedAtMint.getMessage(),
                        curve + ": the mint refusal is our message and names the curve");
                continue;
            }

            assertRefusedAtSign(curve, minted.getPrivate());
            assertRefusedAtDerive(curve, minted.getPrivate(),
                    generate(fips, curve).getPublic());
        }
    }

    /**
     * The control. Without it a module that refused everything would satisfy
     * every refusal above, and the verify arm would be the only thing standing.
     */
    @Test
    public void aStrongCurveDoesAllFourOperations() throws Exception
    {
        byte[] msg = randomMessage();
        KeyPair a = generate(fips, CONTROL_CURVE);
        KeyPair b = generate(fips, CONTROL_CURVE);

        byte[] sig = sign(fips, a.getPrivate(), msg);
        Assertions.assertTrue(verify(fips, a.getPublic(), msg, sig),
                CONTROL_CURVE + ": must verify its own signature");

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", fips);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);
        Assertions.assertTrue(ka.generateSecret().length > 0,
                CONTROL_CURVE + ": must derive");
    }

    private static void assertRefusedAtSign(String curve, PrivateKey priv)
    {
        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                () ->
                {
                    Signature s = Signature.getInstance("SHA256withECDSA", fips);
                    s.initSign(priv);
                },
                curve + ": signing must be refused");

        Assertions.assertEquals(InvalidKeyException.class, ex.getClass(),
                curve + ": the sign refusal must be the canonical type exactly");
        // Verbatim carriage, asserted without pinning OpenSSL's wording, which
        // differs by module and carries a per-run hex prefix.
        Assertions.assertEquals(nativeCause(curve, ex).getMessage(), ex.getMessage(),
                curve + ": the sign refusal must carry the provider's text verbatim");
    }

    private static void assertRefusedAtDerive(String curve, PrivateKey priv, PublicKey peer)
    {
        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class,
                () ->
                {
                    KeyAgreement ka = KeyAgreement.getInstance("ECDH", fips);
                    ka.init(priv);
                    ka.doPhase(peer, true);
                    ka.generateSecret();
                },
                curve + ": agreement must be refused");

        Assertions.assertEquals(InvalidKeyException.class, ex.getClass(),
                curve + ": the derive refusal must be the canonical type exactly");
        Assertions.assertEquals(ECDH_INIT_PREFIX + nativeCause(curve, ex).getMessage(),
                ex.getMessage(),
                curve + ": the derive refusal must state what was refused and carry"
                        + " the provider's text verbatim");
    }

    /** The refusal must come from the native layer, not from a Java-side guess. */
    private static OpenSSLException nativeCause(String curve, Throwable ex)
    {
        Throwable cause = ex.getCause();
        Assertions.assertNotNull(cause, curve + ": the refusal must carry its native cause");
        Assertions.assertTrue(cause instanceof OpenSSLException,
                curve + ": the cause must be the native refusal; got " + cause.getClass());
        return (OpenSSLException) cause;
    }

    private static byte[] randomMessage()
    {
        byte[] msg = new byte[16 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(msg);
        return msg;
    }

    private static KeyPair generate(Provider provider, String curve) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    private static byte[] sign(Provider provider, PrivateKey priv, byte[] msg) throws Exception
    {
        Signature s = Signature.getInstance("SHA256withECDSA", provider);
        s.initSign(priv);
        s.update(msg);
        return s.sign();
    }

    private static boolean verify(Provider provider, PublicKey pub, byte[] msg, byte[] sig)
        throws Exception
    {
        Signature v = Signature.getInstance("SHA256withECDSA", provider);
        v.initVerify(pub);
        v.update(msg);
        return v.verify(sig);
    }
}
