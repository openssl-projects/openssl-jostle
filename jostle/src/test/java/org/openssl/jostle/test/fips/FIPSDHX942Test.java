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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.DSAParameterSpec;

/**
 * The case WI-11 exists for: a q-carrying DH key survives {@code getEncoded()}
 * in the X9.42 form, so it can be handed to JSLFIPS and used.
 *
 * <p>The FIPS modules refuse {@code derive} on a key with no subgroup order
 * ({@code JO_DH_Q_REQUIRED}). Before WI-11 every Jostle DH key degraded to
 * PKCS#3 on encoding, so the q needed to satisfy that check could not be
 * carried across a provider boundary at all.
 *
 * <p>Fixtures are generated through JSL and crossed by encoding, the sanctioned
 * route: explicit-parameter generation is exactly what a FIPS module may refuse
 * (named-group substitution), so the parameters come from BC's DSA generator
 * and the keys from mainline.
 */
public class FIPSDHX942Test
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final ASN1ObjectIdentifier DH_PUBLIC_NUMBER =
            new ASN1ObjectIdentifier("1.2.840.10046.2.1");

    private static DHDomainParameterSpec x942;
    private static DHParameterSpec pkcs3;

    @BeforeAll
    static void before() throws Exception
    {
        FIPSTestUtil.assumeFipsProvider();
        // The fixtures are generated through the BASE provider; the FIPS task
        // registers only JSLFIPS.
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DSA", "BC");
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
     * Encode under JSL, decode through the FIPS KeyFactory, derive under the
     * module — and get the same secret. Asserting the OID as well as the
     * derive, because a decode that quietly dropped q would still produce a
     * usable-looking key on mainline.
     */
    @Test
    public void x942KeyCrossesIntoTheModuleAndDerives() throws Exception
    {
        KeyPair a = jslPair(x942);
        KeyPair b = jslPair(x942);
        byte[] viaJsl = agree(JSL, a.getPrivate(), b.getPublic());

        PrivateKey fipsPriv = FIPSTestUtil.crossPrivate(a.getPrivate(), "DH", FIPS);
        PublicKey fipsPub = FIPSTestUtil.crossPublic(b.getPublic(), "DH", FIPS);

        Assertions.assertEquals(DH_PUBLIC_NUMBER,
                SubjectPublicKeyInfo.getInstance(fipsPub.getEncoded())
                        .getAlgorithm().getAlgorithm(),
                "the re-encoded key must still be X9.42, or q was lost in the crossing");
        Assertions.assertTrue(Arrays.areEqual(viaJsl, agree(FIPS, fipsPriv, fipsPub)),
                "the module must derive the same secret as mainline");
    }

    /**
     * The contrast that makes the test above mean something: the SAME domain
     * parameters without q are still refused by the module, so the success
     * above is q's doing and not a general loosening.
     */
    @Test
    public void pkcs3KeyIsStillRefusedByTheModule() throws Exception
    {
        PrivateKey fipsPriv =
                FIPSTestUtil.crossPrivate(jslPair(pkcs3).getPrivate(), "DH", FIPS);

        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> KeyAgreement.getInstance("DH", FIPS).init(fipsPriv));
        Assertions.assertEquals(
                "DH key or parameters without subgroup order q are not supported "
                        + "by the loaded provider",
                e.getMessage());
    }
}
