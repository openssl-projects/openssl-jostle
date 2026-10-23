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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.jcajce.spec.DHExtendedPublicKeySpec;
import org.openssl.jostle.test.dh.DHTest;
import org.openssl.jostle.test.dh.KeyAgreementCalls;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * The ffdhe2048 subgroup-membership cells from
 * {@code DHExtendedPublicKeySpecTest}, under JSLFIPS. ffdhe2048 is a
 * FIPS-approved named group generated directly through the FIPS provider —
 * unlike the DSA-style group elsewhere in that file, no JSL-then-cross-encode
 * fixture dance is needed here.
 */
public class FIPSDHExtendedPublicKeySpecTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static DHDomainParameterSpec ffdhe2048;

    @BeforeAll
    static void before() throws Exception
    {
        FIPSTestUtil.assumeFipsProvider();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", FIPS);
        kpg.initialize(2048);
        DHParameterSpec params = ((DHPublicKey) kpg.generateKeyPair().getPublic()).getParams();
        // A named-group key is PKCS#3 and reports no q; RFC 7919 primes are safe, so q = (p - 1) / 2.
        ffdhe2048 = new DHDomainParameterSpec(params.getP(),
                params.getP().subtract(BigInteger.ONE).shiftRight(1), params.getG());
    }

    /**
     * Same as the base {@code ffdhe2048RefusesYOutsideTheSubgroupAndAcceptsYInIt}
     * cell, under JSLFIPS.
     */
    @Test
    public void ffdhe2048RefusesYOutsideTheSubgroupAndAcceptsYInIt() throws Exception
    {
        KeyFactory fipsKf = KeyFactory.getInstance("DH", FIPS);

        for (BigInteger badY : new BigInteger[]{BigInteger.valueOf(7), BigInteger.valueOf(11)})
        {
            InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> fipsKf.generatePublic(new DHExtendedPublicKeySpec(badY, ffdhe2048)),
                    "y=" + badY);
            Assertions.assertEquals("public value failed the DH public-key check", e.getMessage(), "y=" + badY);
        }

        PublicKey accepted = fipsKf.generatePublic(
                new DHExtendedPublicKeySpec(BigInteger.valueOf(2), ffdhe2048));
        Assertions.assertNotNull(accepted);
    }

    /** Same as the base X509EncodedKeySpec cell, under JSLFIPS. */
    @Test
    public void ffdhe2048RefusesYOutsideTheSubgroupViaX509EncodedKeySpecToo() throws Exception
    {
        KeyFactory fipsKf = KeyFactory.getInstance("DH", FIPS);
        KeyPair peer = KeyPairGenerator.getInstance("DH", FIPS).generateKeyPair();
        BigInteger badY = BigInteger.valueOf(7);

        byte[] validEncoded = fipsKf.generatePublic(
                new DHExtendedPublicKeySpec(((DHPublicKey) peer.getPublic()).getY(), ffdhe2048)).getEncoded();
        SubjectPublicKeyInfo spki =
                SubjectPublicKeyInfo.getInstance(validEncoded);
        SubjectPublicKeyInfo badSpki = new SubjectPublicKeyInfo(
                spki.getAlgorithm(), new ASN1Integer(badY));
        byte[] badEncoded = badSpki.getEncoded();

        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> fipsKf.generatePublic(new X509EncodedKeySpec(badEncoded)));
        Assertions.assertEquals("public value failed the DH public-key check", e.getMessage());
    }

    /**
     * A named-group key reports the PKCS#3 form, its key's type; a peer rebuilt from those parameters through
     * DHExtendedPublicKeySpec is the same form, and agrees.
     */
    @Test
    public void paramsRoundTripThroughTheExtendedSpecAndAgree() throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        g.initialize(2048);
        KeyPair a = g.generateKeyPair();
        KeyPair b = g.generateKeyPair();
        DHPublicKey bPub = (DHPublicKey) b.getPublic();
        Assertions.assertFalse(bPub.getParams() instanceof DHDomainParameterSpec);
        PublicKey rebuilt = KeyFactory.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME)
                .generatePublic(new DHExtendedPublicKeySpec(bPub.getY(), bPub.getParams()));
        Assertions.assertArrayEquals(secretWith(a.getPrivate(), b.getPublic()), secretWith(a.getPrivate(), rebuilt));
    }

    private static byte[] secretWith(PrivateKey priv, PublicKey pub) throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        ka.init(priv);
        KeyAgreementCalls.phase(ka, pub);
        return KeyAgreementCalls.secret(ka);
    }

    /** The import range checks hold in the module too: x in [1, q-1] on a known group, y in range and subgroup. */
    @Test
    public void keyValuesAreRangeCheckedAtImport() throws Exception
    {
        BigInteger p = ffdhe2048.getP();
        BigInteger q = ffdhe2048.getQ();
        BigInteger g = ffdhe2048.getG();
        KeyFactory kf = KeyFactory.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertNotNull(kf.generatePrivate(new DHPrivateKeySpec(q.subtract(BigInteger.ONE), p, g)));
        for (BigInteger x : new BigInteger[]{q, q.add(BigInteger.ONE), p})
        {
            InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new DHPrivateKeySpec(x, p, g)));
            Assertions.assertEquals("DH x is outside its range: [1, q-1] with q, [1, p-2] without",
                    e.getMessage());
        }
        Assertions.assertNotNull(kf.generatePublic(new DHPublicKeySpec(BigInteger.valueOf(2), p, g)));
        for (BigInteger y : new BigInteger[]{BigInteger.ONE, p.subtract(BigInteger.ONE), p, p.add(BigInteger.ONE)})
        {
            InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePublic(new DHPublicKeySpec(y, p, g)));
            Assertions.assertEquals("public value failed the DH public-key check", e.getMessage());
        }
    }

    /** A DHX PKCS#8 whose derived public value falls outside the q-subgroup is refused by the module's factory. */
    @Test
    public void dhxPrivateKeyWithAPublicValueOutsideTheSubgroupIsRefused() throws Exception
    {
        BigInteger p = ffdhe2048.getP();
        BigInteger q = ffdhe2048.getQ();
        BigInteger x = new BigInteger(255, new SecureRandom()).setBit(0).setBit(254);
        KeyFactory kf = KeyFactory.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        byte[] bad = DHTest.x942PrivateKeyInfo(p, q, p.subtract(BigInteger.valueOf(2)), x);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePrivate(new PKCS8EncodedKeySpec(bad)));
        Assertions.assertEquals("public value failed the DH public-key check", e.getMessage());
        Assertions.assertNotNull(kf.generatePrivate(new PKCS8EncodedKeySpec(
                DHTest.x942PrivateKeyInfo(p, q, BigInteger.valueOf(4), x))));
    }

    /** An even modulus is refused at the boundary by the module's provider too. */
    @Test
    public void evenModulusIsRefusedTyped() throws Exception
    {
        BigInteger even = ffdhe2048.getP().add(BigInteger.ONE);
        KeyFactory kf = KeyFactory.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePublic(new DHPublicKeySpec(BigInteger.valueOf(4), even, BigInteger.valueOf(2))));
        Assertions.assertEquals("DH prime p must be odd", e.getMessage());
        KeyPairGenerator g = KeyPairGenerator.getInstance("DH", JostleFIPSProvider.PROVIDER_NAME);
        InvalidAlgorithmParameterException ie = Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> g.initialize(new DHParameterSpec(even, BigInteger.valueOf(2))));
        Assertions.assertEquals("DHParameterSpec p must be odd", ie.getMessage());
    }
}
