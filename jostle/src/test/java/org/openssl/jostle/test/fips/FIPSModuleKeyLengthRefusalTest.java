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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * A key the FIPS module refuses as too short surfaces through the checked type the JCA method declares:
 * InvalidKeyException from Mac.init for HMAC, InvalidKeySpecException from SecretKeyFactory.generateSecret for
 * HKDF, KBKDF, SSKDF and SSHKDF. Whether the module refuses depends on fipsinstall configuration (the hmac, hkdf,
 * kbkdf, sskdf and sshkdf key checks, 112 bits); as installed here, 3.5.8 refuses and 3.1.2 accepts. So every cell
 * is both-branch: the raw module refusal is measured first at the native interface, where it is the unchecked
 * OpenSSLException the provider must translate, and the JCA call is then required to refuse with the checked type
 * exactly when the module refused, or else to agree with JSL. A key at the 14-byte floor works everywhere.
 */
public class FIPSModuleKeyLengthRefusalTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One below the floor, and well below it. */
    private static final int[] SHORT = {FIPSTestUtil.HMAC_MIN_KEY_BYTES - 1, 8};

    private final MacServiceNI macNI = FIPSNISelector.MacServiceNI;
    private final KdfNI kdfNI = FIPSNISelector.KdfNI;

    private static final byte[] H20 = new byte[20];
    private static final byte[] INFO = {1, 2, 3, 4};

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void hmacKeyRefusalIsInvalidKeyException() throws Exception
    {
        assertContract("HMAC", InvalidKeyException.class);
    }

    @Test
    public void hkdfKeyRefusalIsInvalidKeySpecException() throws Exception
    {
        assertContract("HKDF", InvalidKeySpecException.class);
    }

    @Test
    public void kbkdfKeyRefusalIsInvalidKeySpecException() throws Exception
    {
        assertContract("KBKDF", InvalidKeySpecException.class);
    }

    @Test
    public void sskdfKeyRefusalIsInvalidKeySpecException() throws Exception
    {
        assertContract("SSKDF", InvalidKeySpecException.class);
    }

    @Test
    public void sshkdfKeyRefusalIsInvalidKeySpecException() throws Exception
    {
        assertContract("SSHKDF", InvalidKeySpecException.class);
    }

    private void assertContract(String family, Class<? extends GeneralSecurityException> checked) throws Exception
    {
        byte[] floor = randomBytes(FIPSTestUtil.HMAC_MIN_KEY_BYTES);
        Assertions.assertNull(rawRefusal(family, floor), family + ": the module refused a key at the floor");
        Assertions.assertArrayEquals(jca(JSL, family, floor), jca(FIPS, family, floor), family + " at the floor");

        for (int len : SHORT)
        {
            byte[] key = randomBytes(len);
            String label = family + " " + len + "-byte key";
            OpenSSLException raw = rawRefusal(family, key);
            if (raw == null)
            {
                // Not configured to check: the derivation is real and matches JSL, which has no floor.
                Assertions.assertArrayEquals(jca(JSL, family, key), jca(FIPS, family, key), label);
                continue;
            }
            Assertions.assertTrue(raw.getMessage().startsWith("OpenSSL Error:"), label + ": " + raw.getMessage());
            Assertions.assertTrue(raw.getMessage().contains("invalid key length"), label + ": " + raw.getMessage());

            GeneralSecurityException e = Assertions.assertThrows(checked, () -> jca(FIPS, family, key), label);
            Assertions.assertTrue(e.getCause() instanceof OpenSSLException, label + ": cause " + e.getCause());
            Assertions.assertTrue(e.getMessage().contains("invalid key length"), label + ": " + e.getMessage());
        }
    }

    /**
     * The module's own answer at the native interface: null if it accepts the key, else the unchecked
     * OpenSSLException it refuses with. A checked exception here is not caught: the raw refusal is expected to be
     * the unchecked type, so anything else fails the cell.
     */
    private OpenSSLException rawRefusal(String family, byte[] key) throws GeneralSecurityException
    {
        byte[] out = new byte[32];
        try
        {
            switch (family)
            {
            case "HMAC":
                long ref = macNI.allocateMac("HMAC", "SHA-256");
                try
                {
                    macNI.engineInit(ref, key, null, null, 0);
                }
                finally
                {
                    macNI.dispose(ref);
                }
                return null;
            case "HKDF":
                kdfNI.handleErrorCodes(kdfNI.hkdf(key, H20, INFO, "SHA-256", out, 0, out.length));
                return null;
            case "KBKDF":
                kdfNI.handleErrorCodes(kdfNI.kbkdf("COUNTER", "HMAC", "SHA-256", null, key, null, INFO, null,
                        32, 0, 0, out, 0, out.length));
                return null;
            case "SSKDF":
                kdfNI.handleErrorCodes(kdfNI.sskdf("SHA-256", key, INFO, out, 0, out.length));
                return null;
            case "SSHKDF":
                kdfNI.handleErrorCodes(kdfNI.sshkdf("SHA-256", key, H20, H20, "A", out, 0, out.length));
                return null;
            default:
                throw new IllegalArgumentException(family);
            }
        }
        catch (OpenSSLException e)
        {
            return e;
        }
    }

    /**
     * The same operation through the JCA on {@code provider}; the output is compared between JSL and JSLFIPS.
     */
    private static byte[] jca(String provider, String family, byte[] key) throws GeneralSecurityException
    {
        if (family.equals("HMAC"))
        {
            Mac mac = Mac.getInstance("HmacSHA256", provider);
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(INFO);
        }
        KeySpec spec;
        String name;
        switch (family)
        {
        case "HKDF":
            name = "HKDF-SHA256";
            spec = new HKDFParameterSpec(key, H20, INFO, 32);
            break;
        case "KBKDF":
            name = "KBKDF-HMAC-SHA256";
            spec = new KBKDFParameterSpec(key, null, INFO, null, KBKDFParameterSpec.Mode.COUNTER, 32, false, false,
                    32);
            break;
        case "SSKDF":
            name = "SSKDF-SHA256";
            spec = new SSKDFParameterSpec(key, INFO, 32);
            break;
        case "SSHKDF":
            name = "SSHKDF-SHA256";
            spec = new SSHKDFParameterSpec(key, H20, H20, SSHKDFParameterSpec.KeyType.INITIAL_IV_CLIENT_TO_SERVER, 32);
            break;
        default:
            throw new IllegalArgumentException(family);
        }
        return SecretKeyFactory.getInstance(name, provider).generateSecret(spec).getEncoded();
    }

    private static byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }
}
