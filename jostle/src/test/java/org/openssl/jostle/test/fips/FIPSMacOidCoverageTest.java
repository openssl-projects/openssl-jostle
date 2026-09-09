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
import org.openssl.jostle.test.provider.MacOidCoverageTest;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * MT-83: the FIPS twin of {@link MacOidCoverageTest}.
 *
 * <p>The gap was shared by both providers, which is exactly why the
 * cross-provider parity guard could not see it — it compares our two surfaces
 * to each other. Both halves are therefore pinned against the same external
 * reference, RFC 8018 Appendix B.1.1, reused from the base test so the two
 * lists cannot drift apart.
 *
 * <p>All seven digests are served by JSLFIPS on both 3.1.2 and 3.5.8, so no
 * per-module gating is needed.
 */
public class FIPSMacOidCoverageTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static Provider fips;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void everyPkcs5HmacOidResolvesToItsNamedAlgorithm() throws Exception
    {
        byte[] keyBytes = new byte[32];
        RANDOM.nextBytes(keyBytes);
        byte[] msg = new byte[1 + RANDOM.nextInt(128)];
        RANDOM.nextBytes(msg);

        for (String[] row : MacOidCoverageTest.PKCS5_HMAC_OIDS)
        {
            Mac byName = Mac.getInstance(row[1], fips);
            byName.init(new SecretKeySpec(keyBytes, row[1]));
            byte[] expected = byName.doFinal(msg);

            Mac byOid = Mac.getInstance(row[0], fips);
            byOid.init(new SecretKeySpec(keyBytes, row[1]));

            Assertions.assertTrue(Arrays.areEqual(expected, byOid.doFinal(msg)),
                    row[0] + " must compute the same tag as " + row[1] + " on JSLFIPS");
        }
    }
}
