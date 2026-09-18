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

package org.openssl.jostle.test.xec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RFC 6637 §7 SP 800-56C one-step KDF applied to X25519 / X448 — BC's
 * registered {@code X25519withSHA{256,384,512}CKDF} /
 * {@code X448withSHA{256,384,512}CKDF} names. Curve-bound (see
 * {@link org.openssl.jostle.jcajce.provider.xec.XDHWithCKDFKeyAgreementSpi}'s
 * class javadoc) and sealed like {@code ECWithCKDFKeyAgreementSpi} — a KDF
 * agreement yields keys only through {@code generateSecret(String)}.
 */
public class XDHCKDFAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** AES-128/192/256 key wrap, as {@code KeyAgreementKDF.wrapKeyLenBytes} recognises. */
    private static final String[] WRAP_OIDS = {
            "2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.45"
    };

    private static final String[] CURVES = {"X25519", "X448"};
    private static final String[] DIGESTS = {"SHA256", "SHA384", "SHA512"};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static String name(String curve, String digest)
    {
        return curve + "with" + digest + "CKDF";
    }

    private static KeyPair generate(String curve) throws Exception
    {
        return KeyPairGenerator.getInstance(curve, JSL).generateKeyPair();
    }

    private static String otherCurve(String curve)
    {
        return "X25519".equals(curve) ? "X448" : "X25519";
    }

    private static PrivateKey bcPrivate(String curve, PrivateKey k) throws Exception
    {
        return KeyFactory.getInstance(curve, BC)
                .generatePrivate(new PKCS8EncodedKeySpec(k.getEncoded()));
    }

    private static PublicKey bcPublic(String curve, PublicKey k) throws Exception
    {
        return KeyFactory.getInstance(curve, BC)
                .generatePublic(new X509EncodedKeySpec(k.getEncoded()));
    }

    /** Every registered name, both directions (JSL agreement vs BC agreement over the same keys), random inputs. */
    @Test
    public void everyNameAgreesWithBouncyCastleBothDirections() throws Exception
    {
        for (String curve : CURVES)
        {
            for (String digest : DIGESTS)
            {
                String name = name(curve, digest);
                for (int trial = 0; trial < 6; trial++)
                {
                    KeyPair alice = generate(curve);
                    KeyPair bob = generate(curve);
                    byte[] param = new byte[16 + RANDOM.nextInt(48)];
                    RANDOM.nextBytes(param);

                    for (String wrapOid : WRAP_OIDS)
                    {
                        KeyAgreement jsl = KeyAgreement.getInstance(name, JSL);
                        jsl.init(alice.getPrivate(), new UserKeyingMaterialSpec(param));
                        jsl.doPhase(bob.getPublic(), true);
                        byte[] jslKek = jsl.generateSecret(wrapOid).getEncoded();

                        KeyAgreement bc = KeyAgreement.getInstance(name, BC);
                        bc.init(bcPrivate(curve, alice.getPrivate()),
                                new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(param));
                        bc.doPhase(bcPublic(curve, bob.getPublic()), true);
                        byte[] bcKek = bc.generateSecret(wrapOid).getEncoded();

                        Assertions.assertArrayEquals(bcKek, jslKek,
                                name + " wrap=" + wrapOid + ": derived KEK differs from BC");
                    }
                }
            }
        }
    }

    @Test
    public void rawSharedSecretIsRefused() throws Exception
    {
        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");

            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair alice = generate(curve);
                KeyPair bob = generate(curve);
                KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
                ka.init(alice.getPrivate(), new UserKeyingMaterialSpec(new byte[16]));
                ka.doPhase(bob.getPublic(), true);
                ka.generateSecret();
            }, name + ": raw generateSecret() must be refused");

            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair alice = generate(curve);
                KeyPair bob = generate(curve);
                KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
                ka.init(alice.getPrivate(), new UserKeyingMaterialSpec(new byte[16]));
                ka.doPhase(bob.getPublic(), true);
                try
                {
                    ka.generateSecret(new byte[128], 0);
                }
                catch (ShortBufferException e)
                {
                    throw new AssertionError(e);
                }
            }, name + ": raw generateSecret(byte[],int) must be refused");
        }
    }

    @Test
    public void missingParamIsRefusedTyped() throws Exception
    {
        for (String curve : CURVES)
        {
            for (String digest : DIGESTS)
            {
                String name = name(curve, digest);
                KeyPair alice = generate(curve);

                Assertions.assertThrows(InvalidKeyException.class,
                        () -> KeyAgreement.getInstance(name, JSL).init(alice.getPrivate()),
                        name + ": init(Key) with no Param must be refused typed");

                Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                        () -> KeyAgreement.getInstance(name, JSL).init(alice.getPrivate(),
                                new UserKeyingMaterialSpec(null)),
                        name + ": a null Param must be refused typed");

                Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                        () -> KeyAgreement.getInstance(name, JSL).init(alice.getPrivate(),
                                new UserKeyingMaterialSpec(new byte[0])),
                        name + ": an empty Param must be refused typed");
            }
        }
    }

    @Test
    public void foreignParameterSpecIsRefusedTyped() throws Exception
    {
        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair alice = generate(curve);
            KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
            Assertions.assertThrows(InvalidAlgorithmParameterException.class, () ->
                    ka.init(alice.getPrivate(),
                            new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(new byte[16])),
                    name + ": BC's own UserKeyingMaterialSpec must be refused typed");
        }
    }

    /**
     * Curve-bound at init: the LOCAL private key must match the curve this
     * name is registered for. BC raises
     * {@code InvalidKeyException("inappropriate key for X25519withSHA256CKDF")}
     * for the same input.
     */
    @Test
    public void wrongCurveLocalKeyIsRefusedTypedAtInit() throws Exception
    {
        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair wrongCurveKey = generate(otherCurve(curve));

            Assertions.assertThrows(InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, JSL).init(wrongCurveKey.getPrivate(),
                            new UserKeyingMaterialSpec(new byte[16])),
                    name + ": a " + otherCurve(curve) + " private key must be refused typed");

            // BC parity: BC refuses the same input too, same type, at the
            // same site (its own KeyAgreement.init).
            Assertions.assertThrows(InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, BC).init(
                            bcPrivate(otherCurve(curve), wrongCurveKey.getPrivate()),
                            new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(new byte[16])),
                    name + ": BC must also refuse a " + otherCurve(curve) + " private key");
        }
    }

    /**
     * Curve-bound at doPhase too: a correctly-bound LOCAL key with a
     * WRONG-CURVE peer is refused typed. This is inherited from
     * {@code XDHKeyAgreementSpi}'s existing local/peer type-mismatch
     * handling, not new code in the CKDF class — but it is exactly where BC
     * itself has a gap (see pgp-agreement-surface-plan.md §3: BC raises a
     * raw {@code ClassCastException} here instead of a typed refusal), so
     * this cell asserts ONLY the Jostle side; it is not a BC-parity cell.
     */
    @Test
    public void wrongCurvePeerIsRefusedTypedAtDoPhase() throws Exception
    {
        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair local = generate(curve);
            KeyPair wrongCurvePeer = generate(otherCurve(curve));

            KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
            ka.init(local.getPrivate(), new UserKeyingMaterialSpec(new byte[16]));
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> ka.doPhase(wrongCurvePeer.getPublic(), true),
                    name + ": a " + otherCurve(curve) + " peer must be refused typed");
        }
    }

    /** A different UKM (RFC 6637 §8 Param) must derive a different KEK. */
    @Test
    public void differentParamDerivesDifferentKek() throws Exception
    {
        for (String curve : CURVES)
        {
            String name = name(curve, "SHA256");
            KeyPair alice = generate(curve);
            KeyPair bob = generate(curve);
            byte[] param1 = new byte[20];
            byte[] param2 = new byte[20];
            RANDOM.nextBytes(param1);
            RANDOM.nextBytes(param2);

            KeyAgreement ka1 = KeyAgreement.getInstance(name, JSL);
            ka1.init(alice.getPrivate(), new UserKeyingMaterialSpec(param1));
            ka1.doPhase(bob.getPublic(), true);
            byte[] kek1 = ka1.generateSecret(WRAP_OIDS[0]).getEncoded();

            KeyAgreement ka2 = KeyAgreement.getInstance(name, JSL);
            ka2.init(alice.getPrivate(), new UserKeyingMaterialSpec(param2));
            ka2.doPhase(bob.getPublic(), true);
            byte[] kek2 = ka2.generateSecret(WRAP_OIDS[0]).getEncoded();

            Assertions.assertFalse(Arrays.areEqual(kek1, kek2),
                    name + ": different Param derived the same KEK");
        }
    }

    /** Each digest must actually be used. */
    @Test
    public void eachDigestGivesADifferentKey() throws Exception
    {
        for (String curve : CURVES)
        {
            KeyPair alice = generate(curve);
            KeyPair bob = generate(curve);
            byte[] param = new byte[16];
            RANDOM.nextBytes(param);

            byte[][] keks = new byte[DIGESTS.length][];
            for (int i = 0; i < DIGESTS.length; i++)
            {
                KeyAgreement ka = KeyAgreement.getInstance(name(curve, DIGESTS[i]), JSL);
                ka.init(alice.getPrivate(), new UserKeyingMaterialSpec(param));
                ka.doPhase(bob.getPublic(), true);
                keks[i] = ka.generateSecret(WRAP_OIDS[2]).getEncoded();
            }
            Assertions.assertFalse(Arrays.areEqual(keks[0], keks[1]), curve + ": SHA256 and SHA384 must differ");
            Assertions.assertFalse(Arrays.areEqual(keks[1], keks[2]), curve + ": SHA384 and SHA512 must differ");
            Assertions.assertFalse(Arrays.areEqual(keks[0], keks[2]), curve + ": SHA256 and SHA512 must differ");
        }
    }

    /** Every name resolves; there are no OID aliases (PGP has none to negotiate). */
    @Test
    public void everyNameResolves() throws Exception
    {
        for (String curve : CURVES)
        {
            for (String digest : DIGESTS)
            {
                Assertions.assertNotNull(KeyAgreement.getInstance(name(curve, digest), JSL),
                        name(curve, digest) + " must be registered");
            }
        }
    }
}
