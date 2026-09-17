/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.dh;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.jcajce.spec.DHExtendedPublicKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * {@link DHExtendedPublicKeySpec} — importing a peer's DH public value
 * alongside its full domain parameters (q included), the shape
 * {@code JceKeyAgreeRecipient}/bctls-jsl need to complete an X9.42 (FFDHE)
 * agreement without silently downgrading the peer to PKCS#3.
 */
public class DHExtendedPublicKeySpecTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static DHDomainParameterSpec x942;
    private static DHParameterSpec pkcs3;

    @BeforeAll
    public static void beforeAll() throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DSA", BC);
        apg.init(2048);
        DSAParameterSpec dsa = apg.generateParameters().getParameterSpec(DSAParameterSpec.class);
        x942 = new DHDomainParameterSpec(dsa.getP(), dsa.getQ(), dsa.getG());
        pkcs3 = new DHParameterSpec(dsa.getP(), dsa.getG());
    }

    private static KeyPair jslPair(DHParameterSpec spec) throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", JSL);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static byte[] agree(String provider, PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DH", provider);
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    /**
     * The extensions defect, reproduced and fixed: a local X9.42 key and a
     * peer public value imported WITH q agree, and the derived secret is
     * byte-identical to BC's own {@code DHExtendedPublicKeySpec} /
     * {@code DHDomainParameterSpec} import over the same (p, q, g, y).
     */
    @Test
    public void peerImportedWithX942DomainParametersAgreesWithBc() throws Exception
    {
        KeyPair local = jslPair(x942);
        KeyPair peer = jslPair(x942);

        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        PublicKey jslPeerPub = jslKf.generatePublic(
                new DHExtendedPublicKeySpec(((DHPublicKey) peer.getPublic()).getY(), x942));
        byte[] jslSecret = agree(JSL, local.getPrivate(), jslPeerPub);

        KeyFactory bcKf = KeyFactory.getInstance("DH", BC);
        PrivateKey bcLocalPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(local.getPrivate().getEncoded()));
        PublicKey bcPeerPub = bcKf.generatePublic(
                new org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec(
                        ((DHPublicKey) peer.getPublic()).getY(),
                        new org.bouncycastle.jcajce.spec.DHDomainParameterSpec(
                                x942.getP(), x942.getQ(), x942.getG())));
        byte[] bcSecret = agree(BC, bcLocalPriv, bcPeerPub);

        Assertions.assertArrayEquals(bcSecret, jslSecret,
                "agreement over a q-carrying imported peer value must match BC byte for byte");
    }

    /** PKCS#3 (no q) both sides — unchanged behaviour, still works. */
    @Test
    public void peerImportedWithPlainDhParameterSpecStaysPkcs3() throws Exception
    {
        KeyPair local = jslPair(pkcs3);
        KeyPair peer = jslPair(pkcs3);

        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        PublicKey peerPub = jslKf.generatePublic(
                new DHExtendedPublicKeySpec(((DHPublicKey) peer.getPublic()).getY(), pkcs3));
        byte[] viaExtended = agree(JSL, local.getPrivate(), peerPub);

        // Same peer value, imported through the bare DHPublicKeySpec path —
        // must derive identically, proving PKCS#3 import is unaffected.
        PublicKey peerPubPlain = jslKf.generatePublic(
                new javax.crypto.spec.DHPublicKeySpec(
                        ((DHPublicKey) peer.getPublic()).getY(), pkcs3.getP(), pkcs3.getG()));
        byte[] viaPlain = agree(JSL, local.getPrivate(), peerPubPlain);

        Assertions.assertArrayEquals(viaPlain, viaExtended,
                "PKCS#3 import through the new spec must match the existing bare-spec import");
    }

    /**
     * A y outside the subgroup is refused at import (generatePublic), the
     * same site and the same exception TYPE BC uses for the identical
     * input. Measured (bcprov 1.86): BC's
     * {@code KeyFactorySpi.engineGeneratePublic} constructs a
     * {@code BCDHPublicKey}, whose constructor builds a
     * {@code DHPublicKeyParameters} and validates it there, throwing
     * {@code java.security.spec.InvalidKeySpecException} (BC's own
     * {@code ExtendedInvalidKeySpecException} subclass) with the message
     * "Y value does not appear to be in correct group".
     */
    @Test
    public void yOutsideTheSubgroupIsRefusedTyped() throws Exception
    {
        BigInteger badY = BigInteger.valueOf(2);

        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> jslKf.generatePublic(new DHExtendedPublicKeySpec(badY, x942)));
        Assertions.assertEquals("public value failed the DH public-key check", e.getMessage());

        KeyFactory bcKf = KeyFactory.getInstance("DH", BC);
        org.bouncycastle.jcajce.spec.DHDomainParameterSpec bcParams =
                new org.bouncycastle.jcajce.spec.DHDomainParameterSpec(x942.getP(), x942.getQ(), x942.getG());
        InvalidKeySpecException bcE = Assertions.assertThrows(InvalidKeySpecException.class, () ->
                bcKf.generatePublic(new org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec(badY, bcParams)));
        Assertions.assertEquals("Y value does not appear to be in correct group", bcE.getMessage());
    }

    /**
     * The other two OpenSSL public-key-check failure shapes measured for
     * this input: y = 1 (DH_R_CHECK_PUBKEY_TOO_SMALL) and y = p-1
     * (DH_R_CHECK_PUBKEY_TOO_LARGE). Same message either way — one code
     * serves all three reasons, since the remedy does not differ.
     */
    @Test
    public void yEqualToOneAndPMinusOneAreAlsoRefusedTyped() throws Exception
    {
        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);

        for (BigInteger badY : new BigInteger[]{BigInteger.ONE, x942.getP().subtract(BigInteger.ONE)})
        {
            InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> jslKf.generatePublic(new DHExtendedPublicKeySpec(badY, x942)), "y=" + badY);
            Assertions.assertEquals("public value failed the DH public-key check", e.getMessage(), "y=" + badY);
        }
    }

    /**
     * A peer public key that bypasses {@link DHExtendedPublicKeySpec} —
     * decoded straight from an {@code X509EncodedKeySpec} (ASN.1 SPKI,
     * dhpublicnumber form), as a real peer's certificate/handshake value
     * would be — still reaches OpenSSL's public-key check, at doPhase. This
     * is the arm {@code peer_pubkey_check_failed} in dh.c exists for: the
     * import-time check above only runs through
     * {@code dh_make_public_from_components}, which this path never calls.
     */
    @Test
    public void peerDecodedFromX509EncodedKeySpecBypassesImportCheckAndIsRefusedAtDoPhase() throws Exception
    {
        KeyPair local = jslPair(x942);
        KeyPair peer = jslPair(x942);
        BigInteger badY = BigInteger.valueOf(2);

        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        byte[] validEncoded = jslKf.generatePublic(
                new DHExtendedPublicKeySpec(((DHPublicKey) peer.getPublic()).getY(), x942)).getEncoded();
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(validEncoded);
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo badSpki = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                spki.getAlgorithm(), new org.bouncycastle.asn1.ASN1Integer(badY));
        byte[] badEncoded = badSpki.getEncoded();

        // The bad y is inside the SPKI's own encoding, not a spec field —
        // this decode must succeed (no import-time check on this path).
        PublicKey badPub = jslKf.generatePublic(new java.security.spec.X509EncodedKeySpec(badEncoded));

        KeyAgreement ka = KeyAgreement.getInstance("DH", JSL);
        ka.init(local.getPrivate());
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> ka.doPhase(badPub, true));
        Assertions.assertEquals("DH doPhase: peer public value failed the public-key check", e.getMessage());
    }

    /**
     * BouncyCastle's own {@code DHDomainParameterSpec} as the {@code params}
     * argument — same C44 shape J3 fixed for {@code AlgorithmParameters}/
     * {@code KeyPairGenerator}, now inside this spec's own field.
     */
    @Test
    public void foreignDhParameterSpecInsideTheExtendedSpecIsRefusedTyped() throws Exception
    {
        KeyPair peer = jslPair(x942);
        org.bouncycastle.jcajce.spec.DHDomainParameterSpec foreignParams =
                new org.bouncycastle.jcajce.spec.DHDomainParameterSpec(x942.getP(), x942.getQ(), x942.getG());
        DHExtendedPublicKeySpec spec = new DHExtendedPublicKeySpec(
                ((DHPublicKey) peer.getPublic()).getY(), foreignParams);

        KeyFactory jslKf = KeyFactory.getInstance("DH", JSL);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> jslKf.generatePublic(spec));
        Assertions.assertTrue(e.getMessage().contains(foreignParams.getClass().getName()),
                "message must name the refused class: " + e.getMessage());
        Assertions.assertTrue(e.getMessage().contains(DHDomainParameterSpec.class.getName())
                        && e.getMessage().contains(DHParameterSpec.class.getName()),
                "message must name the accepted types: " + e.getMessage());
    }
}
