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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.test.crypto.AESCTSTest;

import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES CBC-CTS through JSLFIPS — the whole {@link AESCTSTest} contract re-run
 * against the FIPS interface library and the FIPS {@code OSSL_LIB_CTX},
 * plus the checks that only make sense on the FIPS side.
 *
 * <p>Inheriting rather than duplicating is deliberate: the CS3 pin, the
 * accumulator, the one-block floor and the padding refusal are all in shared
 * code, so a FIPS-only regression in any of them has to fail the same
 * assertions. What is NOT shared is the native library and lib ctx, which is
 * exactly what this subclass exercises.
 *
 * <p><b>Ungated.</b> Unlike Triple-DES and the Ed/PQC/XDH families, CBC-CTS
 * needs no capability probe: all three key widths fetch under {@code fips=yes}
 * on both supported modules at both fipsinstall configurations, and
 * {@code cts_mode} is settable on every one of them (measured,
 * {@code fips-c-review/probes/cts_probe.c}). So there is no skip branch here —
 * if the module cannot serve it, that is a failure, not an absence.
 */
public class FIPSAESCTSTest extends AESCTSTest
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
     * JSLFIPS and JSL must produce identical bytes and cross-decrypt. They
     * drive different native libraries against different lib ctxs, so this is
     * not implied by either one agreeing with BouncyCastle separately.
     */
    @Test
    public void agreesWithTheBaseProviderBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithTheBaseProviderBothDirections");

        for (int keyLen : new int[]{16, 24, 32})
        {
            for (int trial = 0; trial < 8; trial++)
            {
                byte[] key = randomBytes(sr, keyLen);
                byte[] iv = randomBytes(sr, BLOCK);
                // Both final-block shapes, for the reason the base class's
                // agreement test explains.
                int msgLen = (trial % 2 == 0)
                        ? BLOCK * (1 + sr.nextInt(4))
                        : BLOCK * (1 + sr.nextInt(4)) + 1 + sr.nextInt(15);
                byte[] msg = randomBytes(sr, msgLen);

                byte[] fips = oneShot(XFORM, JostleFIPSProvider.PROVIDER_NAME,
                        Cipher.ENCRYPT_MODE, key, iv, msg);
                byte[] jsl = oneShot(XFORM, JostleProvider.PROVIDER_NAME,
                        Cipher.ENCRYPT_MODE, key, iv, msg);

                Assertions.assertArrayEquals(jsl, fips,
                        "keyLen=" + keyLen + " msgLen=" + msgLen
                                + ": JSLFIPS and JSL must agree byte for byte");
                Assertions.assertArrayEquals(msg,
                        oneShot(XFORM, JostleProvider.PROVIDER_NAME,
                                Cipher.DECRYPT_MODE, key, iv, fips),
                        "JSLFIPS encrypt -> JSL decrypt");
                Assertions.assertArrayEquals(msg,
                        oneShot(XFORM, JostleFIPSProvider.PROVIDER_NAME,
                                Cipher.DECRYPT_MODE, key, iv, jsl),
                        "JSL encrypt -> JSLFIPS decrypt");
            }
        }
    }

    /**
     * The work is done by the FIPS module, not by mainline's default provider.
     * <p>
     * Mainline implements CBC-CTS identically to both modules, so every
     * agreement, chunking and negative test above passes unchanged whichever
     * provider actually ran — asking OpenSSL which one implements it is the
     * only check that can tell them apart. The ChaCha20 row is the control the
     * rule requires: the probe must be able to answer something other than
     * {@code "fips"}, or a stub returning it would pass.
     */
    @Test
    public void cbcCtsIsImplementedByTheFipsModule()
    {
        FIPSTestUtil.assumeFipsProvider();

        for (String evpName : new String[]{"AES-128-CBC-CTS", "AES-192-CBC-CTS", "AES-256-CBC-CTS"})
        {
            Assertions.assertEquals("fips",
                    FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_CIPHER, evpName),
                    evpName + " must be implemented by the FIPS module");
        }

        Assertions.assertNull(
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_CIPHER, "ChaCha20"),
                "control: the probe must be able to answer something other than \"fips\"");
    }
}
