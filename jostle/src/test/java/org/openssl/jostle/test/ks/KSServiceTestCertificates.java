/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ks;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

/** A self-signed certificate over a test key pair, for key store tests that need a chain or a trusted entry. */
final class KSServiceTestCertificates
{
    private KSServiceTestCertificates()
    {
    }

    static X509Certificate selfSigned(KeyPair pair)
        throws Exception
    {
        X500Name name = new X500Name("CN=Jostle key store test");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                new Date(now - 3600_000L), new Date(now + 3600_000L), name, pair.getPublic());
        String sig = pair.getPrivate().getAlgorithm().startsWith("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder(sig).build(pair.getPrivate())));
    }
}
