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

package org.openssl.jostle.test.util;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.SortedSet;

/**
 * Drives every {@code Cipher} name a provider registers for one family.
 *
 * <p>The operational half of {@link ProviderSurfaceGuard}: that class asserts a
 * name is <i>listed</i> as covered, this one that it <i>works</i>. Twelve AES
 * OID registrations were reachable only through {@code getInstance} plus an
 * assert-non-null — the "registration is not usability" trap.
 *
 * <p>Two properties make it a guard rather than a smoke test: the surface is
 * discovered so a later registration is driven automatically, and an
 * unrecognised name THROWS rather than being skipped. Each round trip also
 * asserts output differs from input, so an identity transform cannot pass.
 */
public final class CipherSurfaceDriver
{
    private CipherSurfaceDriver()
    {
    }

    /** How many key bytes a given registered name needs. */
    public interface KeyLength
    {
        int bytesFor(String upperCasedName);
    }

    /**
     * Drive every registered Cipher name under {@code prefix}, collecting
     * failures rather than stopping at the first.
     *
     * @param provider provider to enumerate and drive
     * @param prefix   SPI class-name prefix identifying the family
     * @param keyAlg   key algorithm for the {@code SecretKeySpec}, e.g. "AES"
     * @param keyLen   key length per name; see {@link KeyLength}
     */
    public static void driveWholeSurface(Provider provider, String prefix, String keyAlg,
                                         KeyLength keyLen, SecureRandom sr)
    {
        SortedSet<String> registered =
                ProviderSurfaceGuard.registeredSurface(provider, prefix, new String[]{"Cipher"});

        Assertions.assertFalse(registered.isEmpty(),
                keyAlg + ": no Cipher services discovered under " + prefix
                        + " — the guard would pass vacuously; check the prefix matches the registrar");

        List<String> failures = new ArrayList<String>();
        for (String entry : registered)
        {
            String name = entry.substring("Cipher.".length());
            try
            {
                drive(provider.getName(), name, keyAlg, keyLen, sr);
            }
            catch (Throwable t)
            {
                failures.add(name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                keyAlg + ": registered Cipher names that could not be driven ("
                        + failures.size() + " of " + registered.size() + "):\n  "
                        + String.join("\n  ", failures));
    }

    /**
     * Drive one registered name. The operation is inferred from the name,
     * since the surface is discovered rather than listed.
     */
    public static void drive(String provider, String name, String keyAlg,
                             KeyLength keyLen, SecureRandom sr) throws Exception
    {
        String n = name.toUpperCase(Locale.ROOT);
        if (n.startsWith("OID."))
        {
            n = n.substring("OID.".length());
        }
        int kl = keyLen.bytesFor(n);

        if (n.contains("WRAP") || n.contains("KW"))
        {
            driveWrap(provider, name, keyAlg, kl, sr);
        }
        else if (n.contains("CCM"))
        {
            // The one shape that will not init without parameters —
            // deliberately, and pinned by aesCCM_initWithoutParams_rejected.
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            driveCipher(provider, name, keyAlg, kl, new GCMParameterSpec(128, nonce), 40, sr);
        }
        else if (n.contains("CTS") || n.contains("CS3PADDING"))
        {
            // Ciphertext stealing needs a whole block to steal from, and a
            // partial final block is the shape worth driving.
            driveCipher(provider, name, keyAlg, kl, null, 37, sr);
        }
        else
        {
            driveCipher(provider, name, keyAlg, kl, null, 32, sr);
        }
    }

    /**
     * Encrypt/decrypt round trip. A null {@code spec} lets the SPI generate
     * its own parameters, as an ordinary caller does, with the decrypt side
     * recovering them through {@code getParameters()}.
     */
    public static void driveCipher(String provider, String name, String keyAlg, int keyLen,
                                   AlgorithmParameterSpec spec, int msgLen, SecureRandom sr)
            throws Exception
    {
        byte[] keyBytes = new byte[keyLen];
        sr.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, keyAlg);
        byte[] msg = new byte[msgLen];
        sr.nextBytes(msg);

        Cipher enc = Cipher.getInstance(name, provider);
        if (spec != null)
        {
            enc.init(Cipher.ENCRYPT_MODE, key, spec, sr);
        }
        else
        {
            enc.init(Cipher.ENCRYPT_MODE, key, sr);
        }
        byte[] ct = enc.doFinal(msg);

        Assertions.assertFalse(Arrays.areEqual(msg, ct),
                name + ": ciphertext equals plaintext — the registration performs no transform");

        Cipher dec = Cipher.getInstance(name, provider);
        if (spec != null)
        {
            dec.init(Cipher.DECRYPT_MODE, key, spec);
        }
        else
        {
            AlgorithmParameters params = enc.getParameters();
            if (params != null)
            {
                dec.init(Cipher.DECRYPT_MODE, key, params);
            }
            else
            {
                dec.init(Cipher.DECRYPT_MODE, key);
            }
        }
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), name + ": round trip");
    }

    /** Wrap/unwrap round trip for the key-wrap registrations. */
    public static void driveWrap(String provider, String name, String keyAlg, int keyLen,
                                 SecureRandom sr) throws Exception
    {
        byte[] kekBytes = new byte[keyLen];
        sr.nextBytes(kekBytes);
        SecretKey kek = new SecretKeySpec(kekBytes, keyAlg);
        // 24 bytes is legal for plain KW (multiple of 8, at least 16) and for
        // KWP alike, so one payload length serves every wrap registration.
        byte[] cekBytes = new byte[24];
        sr.nextBytes(cekBytes);
        SecretKey cek = new SecretKeySpec(cekBytes, keyAlg);

        Cipher w = Cipher.getInstance(name, provider);
        w.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = w.wrap(cek);

        Assertions.assertFalse(Arrays.areEqual(cekBytes, wrapped),
                name + ": wrapped bytes equal the key — the registration performs no transform");

        Cipher u = Cipher.getInstance(name, provider);
        u.init(Cipher.UNWRAP_MODE, kek);
        Assertions.assertArrayEquals(cekBytes,
                u.unwrap(wrapped, keyAlg, Cipher.SECRET_KEY).getEncoded(),
                name + ": wrap round trip");
    }
}
