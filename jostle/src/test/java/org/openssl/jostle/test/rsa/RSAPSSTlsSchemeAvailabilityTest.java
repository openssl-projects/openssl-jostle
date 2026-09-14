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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Installing this provider must not remove the RSA-PSS signature schemes from
 * the JDK's TLS ClientHello.
 *
 * <p>GitHub issue 58, the consequence that made it severe.
 * {@code sun.security.ssl.SignatureScheme} builds its parameter specs in a
 * STATIC INITIALISER: for each of the six rsa_pss_* schemes it resolves
 * {@code Signature.getInstance("RSASSA-PSS")} with NO provider, calls
 * {@code setParameter}, then {@code getParameters()} — and catches
 * RuntimeException by marking the scheme unavailable. While this provider's
 * PSS SPI inherited the throwing {@code SignatureSpi.engineGetParameters}, and
 * while it sat first in the search order, all six vanished from the hello.
 * RFC 8446 forbids PKCS#1 v1.5 in a TLS 1.3 CertificateVerify, so an RSA
 * server certificate could not be authenticated at all. The only warning was
 * under {@code -Djavax.net.debug}.
 *
 * <p>The bytes are parsed rather than the debug log scraped: the logger is not
 * a contract and its format has moved before.
 *
 * <p><b>What this cell actually discriminates, measured.</b> The JDK marks a
 * scheme unavailable only on a RuntimeException — a null return leaves it
 * available with null parameters. So this cell goes red for "getParameters()
 * THREW", not for "getParameters() reported the wrong thing". Falsified: it
 * stayed GREEN with only {@code RSAPSSSignatureSpi.engineGetParameters}
 * reverted (PSS then inherits the null-returning base) and GREEN with only the
 * base override reverted (PSS still answers); it went RED with BOTH reverted,
 * which is the pre-fix tree. Treat it as the symptom guard for the issue and
 * take the per-line discrimination from
 * {@code RSAPSSAlgorithmParametersRegressionTest}, whose cells fail under each
 * single revert.
 *
 * <p><b>This class must run in its own JVM</b> — {@code SignatureScheme}
 * caches availability once per JVM, so the provider has to be installed before
 * any TLS class loads. {@code forkEvery = 1} gives that; nothing else in this
 * class may touch TLS before {@link #rsaPssSchemesSurviveThisProviderBeingFirst()}.
 */
public class RSAPSSTlsSchemeAvailabilityTest
{
    /** RFC 8446 4.2.3: the three rsae and the three pss_pss code points. */
    private static final int[] RSA_PSS_SCHEMES = {0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b};

    /** signature_algorithms, RFC 8446 4.2.3. */
    private static final int EXT_SIGNATURE_ALGORITHMS = 13;

    @Test
    public void rsaPssSchemesSurviveThisProviderBeingFirst()
        throws Exception
    {
        Security.insertProviderAt(new JostleProvider(), 1);

        Set<Integer> offered = clientHelloSignatureSchemes();

        // Vacuity: a parse that found nothing would satisfy every assertion
        // below if they were written as "not absent".
        Assertions.assertFalse(offered.isEmpty(), "no signature schemes parsed from the ClientHello");
        Assertions.assertTrue(offered.size() >= 8,
                "only " + offered.size() + " schemes parsed -- the parser is probably wrong");

        // The control: a non-PSS scheme from the same hello. If the handshake
        // itself broke, this fails too and the failure is not about PSS.
        Assertions.assertTrue(offered.contains(0x0403),
                "control scheme ecdsa_secp256r1_sha256 is absent -- the hello, not PSS, is the problem");

        for (int scheme : RSA_PSS_SCHEMES)
        {
            Assertions.assertTrue(offered.contains(scheme),
                    String.format("rsa_pss scheme 0x%04x is missing from the ClientHello;"
                            + " the JDK disables it when Signature.getParameters() throws", scheme));
        }
    }

    /** Drive one ClientHello and return the signature_algorithms code points. */
    private static Set<Integer> clientHelloSignatureSchemes()
        throws Exception
    {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(true);
        engine.beginHandshake();

        ByteBuffer out = ByteBuffer.allocate(32768);
        engine.wrap(ByteBuffer.allocate(0), out);
        out.flip();
        byte[] record = new byte[out.remaining()];
        out.get(record);

        return parseSignatureSchemes(record);
    }

    private static Set<Integer> parseSignatureSchemes(byte[] record)
    {
        Set<Integer> schemes = new LinkedHashSet<Integer>();

        // TLSPlaintext: type(1) version(2) length(2), then Handshake:
        // msg_type(1) length(3).
        int p = 5 + 4;
        p += 2;   // legacy_version
        p += 32;  // random
        p += 1 + (record[p] & 0xFF);                  // legacy_session_id
        p += 2 + u16(record, p);                      // cipher_suites
        p += 1 + (record[p] & 0xFF);                  // legacy_compression_methods

        int extensionsEnd = p + 2 + u16(record, p);
        p += 2;
        while (p + 4 <= extensionsEnd)
        {
            int type = u16(record, p);
            int length = u16(record, p + 2);
            int body = p + 4;
            if (type == EXT_SIGNATURE_ALGORITHMS)
            {
                int listEnd = body + 2 + u16(record, body);
                for (int q = body + 2; q + 2 <= listEnd; q += 2)
                {
                    schemes.add(u16(record, q));
                }
            }
            p = body + length;
        }
        return schemes;
    }

    private static int u16(byte[] b, int off)
    {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }
}
