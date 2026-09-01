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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.crypto.UpdateOutputCapacityTest;

import javax.crypto.Cipher;
import java.security.Security;

/**
 * The MT-33 update-capacity contract through JSLFIPS.
 *
 * <p><b>Why a twin exists when the Java code is shared.</b> Both providers
 * register the same {@code BlockCipherSpi}, so the threshold logic is one copy
 * and cannot diverge. What it DEPENDS on can: the threshold is
 * {@code blockCipherNi.getUpdateSize(...)}, which resolves to
 * {@code block_cipher_get_update_size} in whichever interface library the
 * provider drives, and the two C trees are independent copies BY DESIGN. Edit
 * that function in one tree only and the shared Java threshold silently
 * disagrees with the other tree's own capacity guard - a caller is told the
 * buffer is fine by Java and then refused by C. The trees are byte-identical
 * today (verified: check-tree-parity.py, 106 twins, 0 violations); this is what
 * notices when they stop being.
 *
 * <p>By contrast a null-key refusal needs no twin: it is decided in shared Java
 * before any NI call, so there is no second code path for a twin to reach.
 */
public class FIPSUpdateOutputCapacityTest extends UpdateOutputCapacityTest
{
    @BeforeAll
    static void beforeFips()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Override
    protected String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }

    /**
     * Anti-dormancy: the inherited cases must actually RUN here.
     *
     * <p>A twin that skipped wholesale - because JSLFIPS did not serve one of
     * the pinned transformations on some module version - would look exactly
     * like a passing twin. So assert the three are served rather than letting
     * an absence pass silently. All three are reachable on both supported
     * modules at both fipsinstall configurations: {@code AES/CTS/NoPadding} is
     * registered in its own right, and CBC/PKCS5 and GCM resolve through the
     * bare {@code AES} registration via the JCE's mode/padding fallback.
     *
     * <p>If one of them ever stops being served, this fails BY NAME and the
     * inherited pins stop being credited as coverage.
     */
    @Test
    public void theThreePinnedTransformationsAreServedHere() throws Exception
    {
        for (String xform : new String[]{
                "AES/CBC/PKCS5Padding", "AES/GCM/NoPadding", "AES/CTS/NoPadding"})
        {
            Assertions.assertNotNull(
                    Cipher.getInstance(xform, JostleFIPSProvider.PROVIDER_NAME),
                    xform + ": JSLFIPS must serve this, or the inherited capacity"
                            + " pins are measuring nothing on this leg");
        }
    }
}
