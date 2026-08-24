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
import org.openssl.jostle.test.crypto.AESXTSTest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

/**
 * XTS-AES through JSLFIPS.
 *
 * <p>Inherits the whole {@link AESXTSTest} contract — IEEE 1619 vectors,
 * agreement with the from-spec reference, the key/tweak boundary matrices, the
 * one-shot refusal, the offset-write and aliasing checks — and re-runs every
 * one of them against the FIPS interface library and its {@code OSSL_LIB_CTX}.
 * That is not redundant with the base class: the two drive different native
 * libraries and different lib ctxs, so neither can substitute for the other.
 *
 * <p>On top of the inherited suite this adds the cross-provider agreement
 * (JSLFIPS vs JSL, both directions) and the direct "is the module actually
 * doing the work?" probe — mainline libcrypto implements XTS identically, so
 * behaviour alone cannot tell the two apart.
 *
 * <p>Ungated: XTS was probed servable, with identical behaviour, on both
 * supported FIPS modules (3.1.2 and 3.5.7) at their default and
 * {@code -pedantic} fipsinstall configurations.
 *
 * <p>Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSAESXTSTest extends AESXTSTest
{
    private static final String XFORM = "AES/XTS/NoPadding";

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
     * JSLFIPS and JSL must produce byte-identical XTS output, and each must
     * decrypt what the other produced. Both directions, per the agreement
     * rules — a divergence pinpoints which side is broken.
     */
    @Test
    public void agreesWithBaseProviderBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBaseProviderBothDirections");

        for (int keyLen : new int[]{32, 64})
        {
            for (int trial = 0; trial < 10; trial++)
            {
                byte[] key = distinctHalvesKey(keyLen, sr);
                byte[] tweak = random(16, sr);
                byte[] pt = random(16 + sr.nextInt(256), sr);

                byte[] fipsCt = encryptWith(JostleFIPSProvider.PROVIDER_NAME, key, tweak, pt);
                byte[] jslCt = encryptWith(JostleProvider.PROVIDER_NAME, key, tweak, pt);

                Assertions.assertArrayEquals(jslCt, fipsCt,
                        "JSLFIPS and JSL must agree byte-for-byte; keyLen=" + keyLen + " ptLen=" + pt.length);

                // JSLFIPS encrypts -> JSL decrypts.
                Assertions.assertArrayEquals(pt,
                        decryptWith(JostleProvider.PROVIDER_NAME, key, tweak, fipsCt));

                // JSL encrypts -> JSLFIPS decrypts.
                Assertions.assertArrayEquals(pt,
                        decryptWith(JostleFIPSProvider.PROVIDER_NAME, key, tweak, jslCt));
            }
        }
    }

    /**
     * Mainline libcrypto implements XTS exactly as the module does, so every
     * behavioural test above passes whichever provider did the work. Ask
     * OpenSSL directly instead.
     *
     * <p>The control matters: the probe must be able to answer something other
     * than "fips", or a stub returning "fips" would pass. ChaCha20 is not in
     * the module, so it must come back as something else.
     */
    @Test
    public void xtsIsImplementedByTheFipsModule()
    {
        for (String name : new String[]{"AES-128-XTS", "AES-256-XTS"})
        {
            Assertions.assertEquals("fips",
                    FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_CIPHER, name),
                    name + " must be implemented by the FIPS module, not mainline's default provider");
        }

        Assertions.assertNotEquals("fips",
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_CIPHER, "ChaCha20"),
                "control: the probe must be able to answer something other than \"fips\"");
    }

    /**
     * Registration is not usability. The golden-surface snapshot only
     * enumerates names; this constructs the service and runs it.
     */
    @Test
    public void xtsIsRegisteredAndUsableThroughTheFipsProvider() throws Exception
    {
        Provider p = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertNotNull(p.getService("Cipher", "AES/XTS/NoPadding"),
                "JSLFIPS must register AES/XTS/NoPadding");

        SecureRandom sr = seededRandom("xtsIsRegisteredAndUsableThroughTheFipsProvider");
        byte[] key = distinctHalvesKey(32, sr);
        byte[] tweak = random(16, sr);
        byte[] pt = random(64, sr);

        Assertions.assertArrayEquals(XTSReference.encrypt(key, tweak, pt),
                encryptWith(JostleFIPSProvider.PROVIDER_NAME, key, tweak, pt));
    }

    private static byte[] encryptWith(String provider, byte[] key, byte[] tweak, byte[] pt) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        return c.doFinal(pt);
    }

    private static byte[] decryptWith(String provider, byte[] key, byte[] tweak, byte[] ct) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, provider);
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tweak));
        return c.doFinal(ct);
    }
}
