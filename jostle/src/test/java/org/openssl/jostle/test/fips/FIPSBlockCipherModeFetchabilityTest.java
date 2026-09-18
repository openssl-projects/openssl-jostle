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
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * A name JSLFIPS registers must be usable. AES-OCB is the
 * measured registered-but-unfetchable name (on both 3.1.2 and 3.5.8): OpenSSL
 * refuses {@code EVP_CIPHER_fetch("AES-*-OCB")} in the FIPS lib ctx while GCM
 * fetches fine at the same key sizes. {@code BlockCipherSpi.engineSetMode}
 * now probes fetchability at {@code Cipher.getInstance} time and refuses OCB
 * there, typed, rather than letting it resolve and fail opaquely at
 * {@code init}. No registration changed (there is no dedicated "AES/OCB/..."
 * service to gate — OCB reaches this SPI through the bare "AES" name's JCA
 * form-4 fallback, exactly like every other mode this class serves), so
 * there is no golden-list entry: this is a lookup-time refusal, the same
 * shape as the module's tdes-encrypt-disabled classifier, just checked at
 * {@code engineSetMode} instead of {@code engineInit}.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSBlockCipherModeFetchabilityTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (java.security.Security.getProvider(JSL) == null)
        {
            java.security.Security.addProvider(new JostleProvider());
        }
    }

    /** The measured gap, at every fixed key-size name, on the loaded module. */
    @Test
    public void aesOcbIsRefusedTypedAtGetInstanceOnJslfips()
    {
        for (int keyBits : new int[]{128, 192, 256})
        {
            String xform = "AES" + keyBits + "/OCB/NoPadding";
            NoSuchAlgorithmException ex = Assertions.assertThrows(NoSuchAlgorithmException.class, () ->
                            Cipher.getInstance(xform, FIPS),
                    "AES-" + keyBits + "-OCB must be refused typed at getInstance under JSLFIPS ("
                            + FIPSTestUtil.moduleDescription() + ")");
            Assertions.assertNotNull(ex);
        }
    }

    /** The generic "AES/OCB/NoPadding" name (key size decided at init) is refused the same way. */
    @Test
    public void aesOcbBareNameRefusedTypedAtGetInstance()
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> Cipher.getInstance("AES/OCB/NoPadding", FIPS),
                "AES/OCB/NoPadding must be refused typed at getInstance under JSLFIPS");
    }

    /** JSL is unaffected: it must still serve OCB at every key size. */
    @Test
    public void aesOcbStillServedOnJsl() throws Exception
    {
        for (int keyLen : new int[]{16, 24, 32})
        {
            Cipher c = Cipher.getInstance("AES/OCB/NoPadding", JSL);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(randomBytes(keyLen), "AES"),
                    new GCMParameterSpec(128, randomBytes(12)));
            byte[] ct = c.doFinal(randomBytes(32));
            Assertions.assertTrue(ct.length > 0, "AES-" + (keyLen * 8) + "-OCB must still encrypt on JSL");
        }
    }

    /**
     * Every OTHER (family, mode) pair {@link OSSLCipher} lists resolves and
     * initialises with a valid key on JSLFIPS — the completeness half of the
     * fix: it must refuse OCB specifically, not modes generally.
     */
    @Test
    public void everyOtherModeStillResolvesAndInitialisesOnJslfips()
    {
        List<String> broken = new ArrayList<>();
        int checked = 0;

        for (OSSLCipher cipher : OSSLCipher.values())
        {
            String family = familyName(cipher);
            if (family == null || cipher.getModes() == null)
            {
                continue;
            }
            for (OSSLMode mode : cipher.getModes())
            {
                if (mode == OSSLMode.CCM || mode == OSSLMode.STREAM || mode == OSSLMode.POLY1305)
                {
                    // CCM: dedicated transformation only, not this generic SPI.
                    // STREAM/POLY1305: ChaCha20's fixed-name registrations,
                    // covered by the base ChaCha20AgreementTest family instead
                    // of this generic-mode sweep.
                    continue;
                }
                String suffix = jcaModeSuffix(mode);
                if (suffix == null)
                {
                    continue;
                }
                if (family.equals("AES") && mode == OSSLMode.OCB)
                {
                    // The one deliberate exception - covered by the tests above.
                    continue;
                }

                String xform = family + "/" + suffix + "/NoPadding";
                checked++;
                try
                {
                    Cipher c = Cipher.getInstance(xform, FIPS);
                    int keyLen = keyLenBytes(mode);
                    byte[] key = randomBytes(keyLen);
                    if (needsIv(mode))
                    {
                        int ivLen = mode == OSSLMode.GCM ? 12 : 16;
                        if (mode == OSSLMode.GCM)
                        {
                            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, family),
                                    new GCMParameterSpec(128, randomBytes(ivLen)));
                        }
                        else
                        {
                            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, family),
                                    new IvParameterSpec(randomBytes(ivLen)));
                        }
                    }
                    else
                    {
                        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, family));
                    }
                }
                catch (Exception e)
                {
                    broken.add(xform + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }

        Assertions.assertTrue(checked >= 8,
                "swept only " + checked + " (family, mode) pairs; not measuring the surface");
        Assertions.assertTrue(broken.isEmpty(),
                "modes that should be fetchable but failed on JSLFIPS (" + FIPSTestUtil.moduleDescription()
                        + "):\n  " + String.join("\n  ", broken));
    }

    private static boolean needsIv(OSSLMode mode)
    {
        return mode != OSSLMode.ECB && mode != OSSLMode.WRAP && mode != OSSLMode.WRAP_PAD
                && mode != OSSLMode.WRAP_INV;
    }

    private static int keyLenBytes(OSSLMode mode)
    {
        // Only "AES" reaches here (see familyName above) - the 256-bit
        // variant, so 32 bytes; XTS needs double-length.
        return mode == OSSLMode.XTS ? 64 : 32;
    }

    private static String familyName(OSSLCipher cipher)
    {
        switch (cipher)
        {
            case AES256:
                return "AES";
            default:
                // AES128/AES192 are the same family at a different fixed
                // size - the 256-bit variant above already covers every
                // mode this sweep drives generically. ARIA/CAMELLIA/SM4 are
                // not registered under JSLFIPS at all (no ProvFIPS* class
                // registers them) - a pre-existing, deliberate fact, not
                // something this fix touches. DES_EDE3 IS registered, but
                // its ENCRYPT direction is a separate, already-classified
                // capability (tdes-encrypt-disabled, ProviderCapabilityException) -
                // orthogonal to the lookup-time mode refusal this test
                // covers, so it is left to its own dedicated coverage.
                return null;
        }
    }

    private static String jcaModeSuffix(OSSLMode mode)
    {
        switch (mode)
        {
            case ECB:
                return "ECB";
            case CBC:
                return "CBC";
            case CFB128:
                return "CFB";
            case OFB:
                return "OFB";
            case CTR:
                return "CTR";
            case GCM:
                return "GCM";
            case XTS:
                return "XTS";
            case WRAP:
                return "KW";
            case WRAP_PAD:
                return "KWP";
            default:
                return null;
        }
    }

    private static byte[] randomBytes(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }
}
