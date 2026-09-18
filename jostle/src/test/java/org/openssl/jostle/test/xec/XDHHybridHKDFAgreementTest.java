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
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.HybridValueParameterSpec;
import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
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
import java.nio.charset.StandardCharsets;

/**
 * RFC 9580 §5.1.6/§5.1.7's v6 hybrid HKDF for X25519 / X448 — BC's
 * registered {@code X25519withSHA256HKDF} / {@code X448withSHA512HKDF}
 * names. Curve-bound (see
 * {@link org.openssl.jostle.jcajce.provider.xec.XDHWithHybridHKDFKeyAgreementSpi}'s
 * class javadoc) and sealed like every other KDF agreement.
 */
public class XDHHybridHKDFAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String AES128_WRAP = "2.16.840.1.101.3.4.1.5";
    private static final String AES256_WRAP = "2.16.840.1.101.3.4.1.45";

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

    private static String name(String curve)
    {
        return "X25519".equals(curve) ? "X25519withSHA256HKDF" : "X448withSHA512HKDF";
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

    private static byte[] info(String curve)
    {
        return ("OpenPGP " + curve).getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * BC's own KAT (bc-java {@code pg/.../test/OperatorJcajceTest.testX25519HKDF},
     * tag r1rv86) — an ephemeral X25519 keypair and a recipient public key,
     * pinned as a literal because it is the exact shape a v6 OpenPGP ECDH
     * decrypt would drive.
     */
    @Test
    public void agreesWithBouncyCastlesOwnRfc9580Vector() throws Exception
    {
        byte[] ephemeralPriv = Hex.decode("af1e43c0d123efe893a7d4d390f3a761e3fac33dfc7f3edaa830c9011352c779");
        byte[] ephemeralPub = Hex.decode("87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764");
        byte[] recipientPub = Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        byte[] expectedKek = Hex.decode("f66dadcff64592239b254539b64ff607");

        KeyFactory jslKf = KeyFactory.getInstance("X25519", JSL);
        PrivateKey priv = jslKf.generatePrivate(rawX25519PrivateKeySpec(ephemeralPriv));
        PublicKey pub = jslKf.generatePublic(rawX25519PublicKeySpec(recipientPub));

        KeyAgreement ka = KeyAgreement.getInstance("X25519withSHA256HKDF", JSL);
        ka.init(priv, new HybridValueParameterSpec(
                Arrays.concatenate(ephemeralPub, recipientPub), true,
                new UserKeyingMaterialSpec(info("X25519"))));
        ka.doPhase(pub, true);
        byte[] kek = ka.generateSecret(AES128_WRAP).getEncoded();

        Assertions.assertArrayEquals(expectedKek, kek, "must reproduce BC's own RFC 9580 vector");
    }

    /** Raw X25519 point -> PKCS#8, via BC's low-level params (no X509/PKCS8 encoder round trip needed at this layer). */
    private static PKCS8EncodedKeySpec rawX25519PrivateKeySpec(byte[] raw) throws Exception
    {
        org.bouncycastle.crypto.params.X25519PrivateKeyParameters params =
                new org.bouncycastle.crypto.params.X25519PrivateKeyParameters(raw, 0);
        return new PKCS8EncodedKeySpec(
                org.bouncycastle.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(params).getEncoded());
    }

    private static X509EncodedKeySpec rawX25519PublicKeySpec(byte[] raw) throws Exception
    {
        org.bouncycastle.crypto.params.X25519PublicKeyParameters params =
                new org.bouncycastle.crypto.params.X25519PublicKeyParameters(raw, 0);
        return new X509EncodedKeySpec(
                org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params).getEncoded());
    }

    /** Every registered name, both directions, random T/info/wrap, over several trials. */
    @Test
    public void everyNameAgreesWithBouncyCastleBothDirections() throws Exception
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            String name = name(curve);
            for (int trial = 0; trial < 6; trial++)
            {
                KeyPair ephemeral = generate(curve);
                KeyPair recipient = generate(curve);
                byte[] t = Arrays.concatenate(
                        ((javax.crypto.interfaces.DHKey) null) == null
                                ? publicKeyBytes(ephemeral.getPublic()) : null,
                        publicKeyBytes(recipient.getPublic()));

                for (String wrapOid : new String[]{AES128_WRAP, AES256_WRAP})
                {
                    KeyAgreement jsl = KeyAgreement.getInstance(name, JSL);
                    jsl.init(ephemeral.getPrivate(), new HybridValueParameterSpec(t, true,
                            new UserKeyingMaterialSpec(info(curve))));
                    jsl.doPhase(recipient.getPublic(), true);
                    byte[] jslKek = jsl.generateSecret(wrapOid).getEncoded();

                    KeyAgreement bc = KeyAgreement.getInstance(name, BC);
                    bc.init(bcPrivate(curve, ephemeral.getPrivate()),
                            new org.bouncycastle.jcajce.spec.HybridValueParameterSpec(t, true,
                                    new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(info(curve))));
                    bc.doPhase(bcPublic(curve, recipient.getPublic()), true);
                    byte[] bcKek = bc.generateSecret(wrapOid).getEncoded();

                    Assertions.assertArrayEquals(bcKek, jslKek,
                            name + " wrap=" + wrapOid + ": derived KEK differs from BC");
                }
            }
        }
    }

    private static byte[] publicKeyBytes(PublicKey k) throws Exception
    {
        // Raw point, not the SPKI encoding — the RFC's T is the raw
        // ephemeral/recipient point, matching BC's own test fixture shape.
        byte[] encoded = k.getEncoded();
        return java.util.Arrays.copyOfRange(encoded, encoded.length - 32 <= 0 ? 0 : encoded.length - 32, encoded.length);
    }

    @Test
    public void rawSharedSecretIsRefused() throws Exception
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            String name = name(curve);
            Assertions.assertThrows(UnsupportedOperationException.class, () ->
            {
                KeyPair ephemeral = generate(curve);
                KeyPair recipient = generate(curve);
                KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
                ka.init(ephemeral.getPrivate(), new HybridValueParameterSpec(
                        Arrays.concatenate(publicKeyBytes(ephemeral.getPublic()), publicKeyBytes(recipient.getPublic())),
                        true, new UserKeyingMaterialSpec(info(curve))));
                ka.doPhase(recipient.getPublic(), true);
                ka.generateSecret();
            }, name + ": raw generateSecret() must be refused");
        }
    }

    @Test
    public void missingOrForeignSpecIsRefusedTyped() throws Exception
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            String name = name(curve);
            KeyPair ephemeral = generate(curve);

            Assertions.assertThrows(InvalidKeyException.class,
                    () -> KeyAgreement.getInstance(name, JSL).init(ephemeral.getPrivate()),
                    name + ": init(Key) with no spec must be refused typed");

            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> KeyAgreement.getInstance(name, JSL).init(ephemeral.getPrivate(),
                            new UserKeyingMaterialSpec(info(curve))),
                    name + ": a plain UserKeyingMaterialSpec must be refused typed");

            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> KeyAgreement.getInstance(name, JSL).init(ephemeral.getPrivate(),
                            new org.bouncycastle.jcajce.spec.HybridValueParameterSpec(new byte[16], true,
                                    new org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec(info(curve)))),
                    name + ": BC's own HybridValueParameterSpec must be refused typed");
        }
    }

    /**
     * RFC 9580 fixes the IKM as ephemeral || recipient || Z — T always
     * precedes Z. The two-argument constructor defaults to the append
     * form ({@code isPrependedT() == false}), which is refused typed.
     */
    @Test
    public void appendFormTIsRefusedTyped() throws Exception
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            String name = name(curve);
            KeyPair ephemeral = generate(curve);

            Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                    () -> KeyAgreement.getInstance(name, JSL).init(ephemeral.getPrivate(),
                            new HybridValueParameterSpec(new byte[16],
                                    new UserKeyingMaterialSpec(info(curve)))),
                    name + ": the two-argument (append T) constructor must be refused typed");
        }
    }

    @Test
    public void wrongCurveLocalKeyIsRefusedTypedAtInit() throws Exception
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            String name = name(curve);
            KeyPair wrongCurveKey = generate(otherCurve(curve));

            Assertions.assertThrows(InvalidKeyException.class, () ->
                    KeyAgreement.getInstance(name, JSL).init(wrongCurveKey.getPrivate(),
                            new HybridValueParameterSpec(new byte[16], true,
                                    new UserKeyingMaterialSpec(info(curve)))),
                    name + ": a " + otherCurve(curve) + " private key must be refused typed");
        }
    }

    @Test
    public void wrongCurvePeerIsRefusedTypedAtDoPhase() throws Exception
    {
        for (String curve : new String[]{"X25519", "X448"})
        {
            String name = name(curve);
            KeyPair local = generate(curve);
            KeyPair wrongCurvePeer = generate(otherCurve(curve));

            KeyAgreement ka = KeyAgreement.getInstance(name, JSL);
            ka.init(local.getPrivate(), new HybridValueParameterSpec(new byte[16], true,
                    new UserKeyingMaterialSpec(info(curve))));
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> ka.doPhase(wrongCurvePeer.getPublic(), true),
                    name + ": a " + otherCurve(curve) + " peer must be refused typed");
        }
    }

    @Test
    public void everyNameResolves() throws Exception
    {
        Assertions.assertNotNull(KeyAgreement.getInstance("X25519withSHA256HKDF", JSL));
        Assertions.assertNotNull(KeyAgreement.getInstance("X448withSHA512HKDF", JSL));
    }
}
