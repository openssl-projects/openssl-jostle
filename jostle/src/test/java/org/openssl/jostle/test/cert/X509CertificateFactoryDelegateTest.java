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

package org.openssl.jostle.test.cert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

/**
 * {@code X509CertificateFactorySpi} resolves its delegate from {@code "SUN"} by
 * NAME, and this pins that it still does.
 *
 * <h2>Why this test exists instead of a fault survey</h2>
 *
 * <p>Group C arc 3a set out to give {@code CertificateFactory} a negative-path
 * parity survey and DID NOT, because the survey would have been vacuous. The SPI
 * performs no cryptographic operation and delegates outright:
 *
 * <pre>    this.delegate = CertificateFactory.getInstance("X.509", "SUN");</pre>
 *
 * <p>So on the parse path there is no jostle code to measure. Measured
 * 2026-09-07, all ten fault cells returned the same exception type AND the same
 * message text in the JSL column and the JDK column - because the JDK column
 * resolves to SUN, which is the same object the SPI holds. Two sides of that
 * witness share a source, so it witnesses the sharing and nothing else, and ten
 * ALL_AGREE rows would have read like coverage.
 *
 * <h2>What IS at risk, and is not visible to any fault cell</h2>
 *
 * <p>The delegate is pinned to {@code "SUN"} deliberately. An edit to a plain
 * {@code getInstance("X.509")} would compile, pass every existing test, and
 * silently make the parse resolve by JCA PROVIDER ORDER - so in a JVM where
 * BouncyCastle is installed first, {@code CertificateFactory.getInstance("X.509",
 * jsl)} would quietly be BouncyCastle. No negative-path cell can see that: both
 * providers parse a valid certificate correctly, and both refuse garbage.
 *
 * <h2>Two independent witnesses, both behavioural, neither reflective</h2>
 *
 * <ol>
 *   <li><b>The CRL path is UNWRAPPED.</b> {@code engineGenerateCertificate}
 *       wraps its result in a package-private {@code JSLKeyX509Certificate}, so
 *       the certificate's class is ours whichever provider parsed it. But
 *       {@code engineGenerateCRL} returns the delegate's own object, so its class
 *       names the parsing provider directly.</li>
 *   <li><b>The two providers refuse garbage with DIFFERENT exception classes</b>,
 *       so the class our factory throws also names the delegate.</li>
 * </ol>
 *
 * <p>Both are compared LIVE against SUN and BouncyCastle rather than against a
 * hard-coded class name, and both carry a vacuity guard: if BouncyCastle's answer
 * ever equals SUN's, the witness discriminates nothing and the test FAILS rather
 * than passing emptily.
 *
 * <p>BouncyCastle is installed at position 1 for the duration - ABOVE both JSL
 * and SUN - so that a delegate resolved by JCA order would land on BouncyCastle.
 * Without that, the pin would pass whatever the SPI did, because SUN outranks BC
 * in the default order.
 */
public class X509CertificateFactoryDelegateTest
{
    private Provider jsl;
    private Provider bc;
    private Provider sun;
    /** Whether BouncyCastle was installed BEFORE this test moved it. */
    private boolean bcWasInstalled;

    @BeforeEach
    public void setUp() throws Exception
    {
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        if (jsl == null)
        {
            jsl = new JostleProvider();
            Security.addProvider(jsl);
        }
        sun = Security.getProvider("SUN");
        Assertions.assertNotNull(sun, "the SUN provider is absent; this pin cannot run");

        // Remove and reinsert at position 1 so BC outranks JSL and SUN.
        bcWasInstalled = Security.getProvider("BC") != null;
        Security.removeProvider("BC");
        bc = new BouncyCastleProvider();
        Security.insertProviderAt(bc, 1);
        Assertions.assertEquals("BC", Security.getProviders()[0].getName(),
                "BouncyCastle is not first, so a JCA-order delegate would not land on it"
                        + " and this pin would discriminate nothing");
    }

    @AfterEach
    public void tearDown()
    {
        // Leave the registry as FOUND, which means restoring BC's absence too -
        // otherwise the comment is a claim the code does not honour. forkEvery=1
        // makes the leak harmless in practice; that is a reason the comment must
        // be true, not a reason to skip the restore.
        Security.removeProvider("BC");
        if (bcWasInstalled)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static byte[] cert()
    {
        return Base64.getDecoder().decode(CERT_B64);
    }

    private static byte[] crl()
    {
        return Base64.getDecoder().decode(CRL_B64);
    }

    /**
     * Witness 1: the CRL our factory returns is the one SUN would have parsed.
     *
     * <p>{@code engineGenerateCRL} does not wrap, so the returned object's class
     * IS the delegate's. Compared live against both references.
     */
    @Test
    public void generateCrlReturnsTheSunObjectNotBouncyCastles() throws Exception
    {
        CRL viaJsl = CertificateFactory.getInstance("X.509", jsl)
                .generateCRL(new ByteArrayInputStream(crl()));
        CRL viaSun = CertificateFactory.getInstance("X.509", sun)
                .generateCRL(new ByteArrayInputStream(crl()));
        CRL viaBc = CertificateFactory.getInstance("X.509", bc)
                .generateCRL(new ByteArrayInputStream(crl()));

        // Vacuity guard: if the two references answer alike, nothing below
        // discriminates and a green result would mean nothing.
        Assertions.assertNotEquals(viaSun.getClass(), viaBc.getClass(),
                "SUN and BouncyCastle produce the same CRL class, so this witness"
                        + " cannot tell the two delegates apart");

        Assertions.assertEquals(viaSun.getClass(), viaJsl.getClass(),
                "the JSL CertificateFactory parsed a CRL with " + viaJsl.getClass().getName()
                        + ", not SUN's " + viaSun.getClass().getName()
                        + " - the delegate is no longer pinned to SUN by name");
    }

    /**
     * Witness 2: our factory refuses malformed input the way SUN does.
     *
     * <p>The parse path IS wrapped, so the certificate class cannot be read; the
     * REFUSAL is what escapes unwrapped, and the two references refuse with
     * different classes.
     */
    @Test
    public void garbageIsRefusedWithSunsExceptionClassNotBouncyCastles()
    {
        byte[] garbage = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

        Class<?> viaJsl = refusalClass(jsl, garbage);
        Class<?> viaSun = refusalClass(sun, garbage);
        Class<?> viaBc = refusalClass(bc, garbage);

        Assertions.assertNotNull(viaJsl, "the JSL factory ACCEPTED eight bytes of garbage as a certificate");
        Assertions.assertNotEquals(viaSun, viaBc,
                "SUN and BouncyCastle refuse garbage with the same exception class, so this"
                        + " witness cannot tell the two delegates apart");

        Assertions.assertEquals(viaSun, viaJsl,
                "the JSL CertificateFactory refused garbage with " + viaJsl.getName()
                        + ", not SUN's " + viaSun.getName()
                        + " - the delegate is no longer pinned to SUN by name");
    }

    /**
     * The positive control: whatever the delegate is, a valid certificate must
     * still parse. Without this, a factory that refused EVERYTHING would satisfy
     * witness 2.
     */
    @Test
    public void aValidCertificateStillParses() throws Exception
    {
        Certificate c = CertificateFactory.getInstance("X.509", jsl)
                .generateCertificate(new ByteArrayInputStream(cert()));
        Assertions.assertNotNull(c);
        Assertions.assertEquals("X.509", c.getType());
    }

    private static Class<?> refusalClass(Provider p, byte[] bytes)
    {
        try
        {
            CertificateFactory.getInstance("X.509", p)
                    .generateCertificate(new ByteArrayInputStream(bytes));
            return null;
        }
        catch (Throwable t)
        {
            return t.getClass();
        }
    }

    private static final String CERT_B64 =
            "MIIDFTCCAf2gAwIBAgIUVSbA2ohOLE8j05vqRp0HoFCgcYcwDQYJKoZIhvcNAQEL"
          + "BQAwGjEYMBYGA1UEAwwPSm9zdGxlIFJTQSBUZXN0MB4XDTI2MDYwNTIzNTA1NloX"
          + "DTM2MDYwMjIzNTA1NlowGjEYMBYGA1UEAwwPSm9zdGxlIFJTQSBUZXN0MIIBIjAN"
          + "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtA9sLfgO1/dW9q1w/dyoox6S0C6l"
          + "fWYIwtr+kiuJicBfQ+0Bqm1XRqVhmLUTSadxLMbEY+rQ0Hyq0YNQrgKME68pbX1k"
          + "FQcNk3aS/a+aJ7J2XG/yZih5rHhgxKIjaGDfsBdQPlTueC8IV+3v+h8SweYuOv5y"
          + "aXKcxk+IeN/MzSag/2YqDsBzmN98R0hAGvvVsU9KN6OydTSqDAGJ0ontBoJmqj3N"
          + "5bdwImikjVSYC65frTMcvFgO2gOrRHiMCuqxhR0wLhn2AZote/LdUMIrIhB2wMOQ"
          + "1NiIN1jET8TN9FSVDXjlK+MFRWopx8rdtg3h7Egs1U6WsBQ8jOTQIASm1wIDAQAB"
          + "o1MwUTAdBgNVHQ4EFgQUTlapRpnUiPa9hzCribOp+lqpScgwHwYDVR0jBBgwFoAU"
          + "TlapRpnUiPa9hzCribOp+lqpScgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B"
          + "AQsFAAOCAQEAIS/foqm1TkS68DNfElAWhaabpP8/TBpNF5VTYgMHp9H/NGprGUm5"
          + "DXngGRQgN7WwsJVhuhJJP58qGOVjsuZlwXhN/65l3xDof9JuEAeGGJKkfJZfaF3b"
          + "6mDVlM2m3VCNcCRiuJqllDy/L6/D3t5WFxSizDGM4gYObX3tFnm4keiEohE2gZ8+"
          + "KpudoyLOnsEBxBO/Xv9+cQlfkoU7Pd6N+bDZ6HpoDkFp29iVxtRhPign+5HAl03J"
          + "4BVccBXua58I57YzhfP1YDD1DKK8H3SKzaHTrUkZBZkvAEvmIkOKIIOvJRjkXGlA"
          + "V806dyTKN7aECu5CPJLm9ZlxyuBPFTBE0w==";

    private static final String CRL_B64 =
            "MIIBiTBzAgEBMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDkpvc3RsZSBUZXN0"
          + "IENBFw0yNjA2MDYwMDEwNDhaFw0zNjA2MDMwMDEwNDhaMBUwEwICIAAXDTI2MDYw"
          + "NjAwMTA0OFqgDzANMAsGA1UdFAQEAgIQADANBgkqhkiG9w0BAQsFAAOCAQEAeuBm"
          + "C/c7wjrVsRqOFZiUkEMMMK/Pjwa2MvNNKlly8X39seBfuHDlOXF3k2VgILncf0XC"
          + "RhGGqP76V+89RK0H4rbcEg5oucsAf+eRQANRgZ7/zJQb1d9Ww6yjoEEEJpXTEUe1"
          + "WdTIsEoOWnl/VKTjJ+aW/AcL4bw3WkcxpvUC4yDKkiwrhnd0LR+3nE8fBdxLkks7"
          + "nUODsHAAr5GBFlGvX5YgbfBfwwDhOymv7ykvdjJXOd1KG9r7P3BptOecTWTrogtW"
          + "e8ys2kwz/qbEIWBnT7QIC129EamJ5RS5JWsWs43VoQy8ELj3on7N/WaWZ501m2KB"
          + "g7oHwW/9CNPoDpHBDA==";
}
