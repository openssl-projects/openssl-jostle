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
package org.openssl.jostle.test.spec;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared by {@code KemSharedSecretLengthTest} and its FIPS twin: for each named KEM the provider serves,
 * the encapsulation-side shared-secret length query, the decapsulation size query and a real encapsulation
 * must all give the same length, the secret must round-trip, a window one byte short must be refused, and the
 * two cached facts for a key type (encapsulation and shared-secret length) must not answer for each other.
 */
public final class KemSharedSecretLengths
{
    /** Every KEM parameter set and hybrid group either provider may serve. */
    public static final String[] ALL = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768",
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X448MLKEM1024"};

    private KemSharedSecretLengths()
    {
    }

    /**
     * Checks every name in {@code names} the provider serves, and fails if it serves none of them.
     *
     * @return one line per name, for the log.
     */
    public static String check(Provider provider, String[] names, RandSource rnd) throws Exception
    {
        List<String> rows = new ArrayList<String>();
        int checked = 0;
        for (String name : names)
        {
            if (provider.getService("KeyPairGenerator", name) == null)
            {
                rows.add(name + ": not served by " + provider.getName());
                continue;
            }
            KeyPair kp = KeyPairGenerator.getInstance(name, provider).generateKeyPair();
            PKEYKeySpec pub = ((OSSLKey) kp.getPublic()).getSpec();
            PKEYKeySpec priv = ((OSSLKey) kp.getPrivate()).getSpec();
            SpecNI ni = pub.getSpecNI();

            int queried = ni.encapSecretLength(pub.getReference(), null, rnd);
            int encLen = ni.encap(pub.getReference(), null, new byte[queried], 0, queried, null, 0, 0, rnd);
            byte[] secret = new byte[queried];
            byte[] enc = new byte[encLen];
            ni.encap(pub.getReference(), null, secret, 0, queried, enc, 0, encLen, rnd);
            int decapLen = ni.decap(priv.getReference(), null, enc, 0, encLen, null, 0, 0, rnd);
            byte[] recovered = new byte[decapLen];
            ni.decap(priv.getReference(), null, enc, 0, encLen, recovered, 0, decapLen, rnd);

            Assertions.assertEquals(queried, decapLen, name + ": the encap and decap queries disagree");
            Assertions.assertArrayEquals(secret, recovered, name + ": the secret did not round-trip");
            // Both cached facts for one key type, encapsulation length first: a shared cache would answer the
            // second from the first.
            Assertions.assertEquals(encLen, ni.encapsulationLength(pub.getReference(), pub.getType(), queried, rnd),
                    name + ": the cached encapsulation length differs from the query");
            Assertions.assertEquals(queried, ni.sharedSecretLength(pub.getReference(), pub.getType(), rnd),
                    name + ": the cached shared-secret length differs from the query");
            try
            {
                ni.encap(pub.getReference(), null, new byte[queried - 1], 0, queried - 1, new byte[encLen], 0,
                        encLen, rnd);
                Assertions.fail(name + ": a secret window one byte short was accepted");
            }
            catch (IllegalArgumentException e)
            {
                Assertions.assertEquals("output too small", e.getMessage(), name);
            }
            rows.add(name + ": secret " + queried + " bytes, encapsulation " + encLen + " bytes");
            checked++;
        }
        Assertions.assertTrue(checked > 0, provider.getName() + " serves none of the KEMs");
        return String.join("\n  ", rows);
    }
}
