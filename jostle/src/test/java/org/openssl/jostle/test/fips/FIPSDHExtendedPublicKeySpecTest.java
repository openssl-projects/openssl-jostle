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
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.jcajce.spec.DHExtendedPublicKeySpec;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
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
        DHDomainParameterSpec domain = (DHDomainParameterSpec) params;
        ffdhe2048 = new DHDomainParameterSpec(domain.getP(), domain.getQ(), domain.getG());
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
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(validEncoded);
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo badSpki = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                spki.getAlgorithm(), new org.bouncycastle.asn1.ASN1Integer(badY));
        byte[] badEncoded = badSpki.getEncoded();

        InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                () -> fipsKf.generatePublic(new X509EncodedKeySpec(badEncoded)));
        Assertions.assertEquals("public value failed the DH public-key check", e.getMessage());
    }
}
