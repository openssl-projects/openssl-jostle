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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.JvmProbe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A child JVM for KSLibCtxThreadsIntegrationTest. A PKCS#12 load switches the
 * default lib ctx for its unpacking calls; two threads load while a third
 * digests and a fourth stores, so a switch that were not per thread would show
 * as a failed digest or load. Not a test class: no test filter selects it.
 */
public final class LibCtxThreadsProbe
{
    private LibCtxThreadsProbe()
    {
    }

    public static void main(String[] args) throws Exception
    {
        final Provider jsl = new JostleProvider();
        Provider bc = new BouncyCastleProvider();
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        X500Name n = new X500Name("CN=Threads");
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                n, BigInteger.ONE, new Date(System.currentTimeMillis() - 3600_000L),
                new Date(System.currentTimeMillis() + 3600_000L), n, kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(bc).build(kp.getPrivate())));
        final char[] pw = "changeit".toCharArray();
        KeyStore w = KeyStore.getInstance("PKCS12", jsl);
        w.load(null, null);
        w.setKeyEntry("key", kp.getPrivate(), pw, new Certificate[]{cert});
        w.setCertificateEntry("trusted", cert);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        w.store(out, pw);
        final byte[] file = out.toByteArray();

        final AtomicInteger ok = new AtomicInteger();
        final AtomicInteger failed = new AtomicInteger();
        final StringBuffer errors = new StringBuffer();
        Runnable loader = new Runnable()
        {
            public void run()
            {
                for (int i = 0; i < 15; i++)
                {
                    try
                    {
                        KeyStore k = KeyStore.getInstance("PKCS12", jsl);
                        k.load(new ByteArrayInputStream(file), pw);
                        if (k.size() == 2 && k.getKey("key", pw) != null)
                        {
                            ok.incrementAndGet();
                        }
                        else
                        {
                            failed.incrementAndGet();
                        }
                    }
                    catch (Exception e)
                    {
                        failed.incrementAndGet();
                        errors.append(e).append("; ");
                    }
                }
            }
        };
        Runnable digester = new Runnable()
        {
            public void run()
            {
                for (int i = 0; i < 20000; i++)
                {
                    try
                    {
                        MessageDigest.getInstance("SHA-256", jsl).digest(new byte[64]);
                        ok.incrementAndGet();
                    }
                    catch (Exception e)
                    {
                        failed.incrementAndGet();
                        errors.append(e).append("; ");
                    }
                }
            }
        };
        Runnable storer = new Runnable()
        {
            public void run()
            {
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        KeyStore k = KeyStore.getInstance("PKCS12", jsl);
                        k.load(new ByteArrayInputStream(file), pw);
                        k.store(new ByteArrayOutputStream(), pw);
                        ok.incrementAndGet();
                    }
                    catch (Exception e)
                    {
                        failed.incrementAndGet();
                        errors.append(e).append("; ");
                    }
                }
            }
        };
        Thread[] threads = {new Thread(loader), new Thread(loader), new Thread(digester), new Thread(storer)};
        for (Thread t : threads)
        {
            t.start();
        }
        for (Thread t : threads)
        {
            t.join();
        }
        JvmProbe.emit("ok", Integer.toString(ok.get()));
        JvmProbe.emit("failed", Integer.toString(failed.get()));
        JvmProbe.emit("errors", errors.toString());
    }
}
