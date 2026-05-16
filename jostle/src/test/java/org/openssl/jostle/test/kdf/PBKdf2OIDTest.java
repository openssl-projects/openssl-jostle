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

package org.openssl.jostle.test.kdf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * OID-resolution tests for PBKDF2 (RFC 8018 PKCS#5 v2.1).
 *
 * <p>bcpkix-style code routes KDFs by OID rather than by canonical
 * name — for PBMAC1 (RFC 9045) the protection algorithm carries the
 * PBKDF2 OID plus a separate AlgorithmIdentifier naming the PRF
 * (typically an HMAC OID). The
 * {@link SecretKeyFactory#getInstance(String)} lookup must therefore
 * resolve both the bare {@code id-PBKDF2 = 1.2.840.113549.1.5.12} and
 * each {@code id-hmacWithSHA*} per-PRF OID.
 *
 * <p>This suite covers:
 * <ol>
 *   <li>Lookup-by-OID returns a working factory for every registered
 *       PRF and produces output byte-identical to the lookup-by-name
 *       factory (proves the alias points at the right impl, not at a
 *       PRF-mismatched one).</li>
 *   <li>The bare {@code id-PBKDF2} OID resolves to the default
 *       factory (PRF supplied via {@code PBKDF2KeySpec}).</li>
 *   <li>Negative: a fabricated PKCS#5 OID under the same arc that
 *       isn't registered fails with {@code NoSuchAlgorithmException} —
 *       belt-and-braces against an accidental alias hitting the wrong
 *       slot.</li>
 * </ol>
 */
public class PBKdf2OIDTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    /**
     * For each registered HMAC PRF OID, the SecretKeyFactory looked up
     * by OID must produce the same derived key as the same factory
     * looked up by its canonical name. Run a few random trials per
     * PRF so per-input-quirk bugs surface (CLAUDE.md
     * "Run agreement tests against BouncyCastle, with random inputs"
     * — here we agree against ourselves under two lookup paths).
     */
    @Test
    public void pbkdf2_OIDLookup_matchesNameLookup() throws Exception
    {
        String[][] pairs = {
                {"PBKDF2WithHmacSHA1", "1.2.840.113549.2.7"},
                {"PBKDF2WithHmacSHA224", "1.2.840.113549.2.8"},
                {"PBKDF2WithHmacSHA256", "1.2.840.113549.2.9"},
                {"PBKDF2WithHmacSHA384", "1.2.840.113549.2.10"},
                {"PBKDF2WithHmacSHA512", "1.2.840.113549.2.11"},
                {"PBKDF2WithHmacSHA512-224", "1.2.840.113549.2.12"},
                {"PBKDF2WithHmacSHA512-256", "1.2.840.113549.2.13"},
        };

        for (String[] pair : pairs)
        {
            String name = pair[0];
            String oid = pair[1];

            // Five random trials so an input-specific bug surfaces.
            for (int trial = 0; trial < 5; trial++)
            {
                char[] password = randomChars(12 + trial);
                byte[] salt = new byte[8 + trial];
                RANDOM.nextBytes(salt);
                int iterations = 1000 + trial * 137;
                int keyBits = 128 + trial * 32;

                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);

                SecretKeyFactory byName = SecretKeyFactory.getInstance(name, JostleProvider.PROVIDER_NAME);
                SecretKeyFactory byOid = SecretKeyFactory.getInstance(oid, JostleProvider.PROVIDER_NAME);

                byte[] viaName = byName.generateSecret(spec).getEncoded();
                byte[] viaOid = byOid.generateSecret(spec).getEncoded();

                Assertions.assertTrue(Arrays.areEqual(viaName, viaOid),
                        name + " (" + oid + ") trial " + trial
                                + ": OID lookup produced different output to name lookup");
            }
        }
    }


    /**
     * The bare {@code id-PBKDF2} OID resolves to the default-PRF
     * factory (PRF inferred from the spec). Confirms the OID isn't
     * silently rewriting to a pinned PRF.
     */
    @Test
    public void pbkdf2_idPbkdf2_OID_resolves() throws Exception
    {
        SecretKeyFactory bare = SecretKeyFactory.getInstance("PBKDF2", JostleProvider.PROVIDER_NAME);
        SecretKeyFactory byOid = SecretKeyFactory.getInstance("1.2.840.113549.1.5.12",
                JostleProvider.PROVIDER_NAME);

        char[] password = "test-password".toCharArray();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 2048, 256);

        byte[] fromBare = bare.generateSecret(spec).getEncoded();
        byte[] fromOid = byOid.generateSecret(spec).getEncoded();

        Assertions.assertTrue(Arrays.areEqual(fromBare, fromOid),
                "id-PBKDF2 OID should resolve to the same factory as the bare name");
    }


    /**
     * BC interop: a key derived via the {@code id-hmacWithSHA256} OID
     * lookup on Jostle must match the equivalent computation through
     * BC's name-lookup factory. Proves the OID alias maps to the
     * right PRF (not, say, SHA-1 by accident).
     */
    @Test
    public void pbkdf2_OIDLookup_BCAgreement() throws Exception
    {
        char[] password = "another-test-password".toCharArray();
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 4096, 256);

        SecretKeyFactory joByOid = SecretKeyFactory.getInstance("1.2.840.113549.2.9",
                JostleProvider.PROVIDER_NAME);
        byte[] joKey = joByOid.generateSecret(spec).getEncoded();

        SecretKeyFactory bcByName = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256",
                BouncyCastleProvider.PROVIDER_NAME);
        byte[] bcKey = bcByName.generateSecret(spec).getEncoded();

        Assertions.assertTrue(Arrays.areEqual(joKey, bcKey),
                "Jostle OID lookup must produce same key as BC's name lookup");
    }


    /**
     * A made-up OID in the same arc that we DON'T register must surface
     * as {@link java.security.NoSuchAlgorithmException} from the JCE
     * lookup — proves we haven't accidentally aliased a wildcard.
     */
    @Test
    public void pbkdf2_unregisteredOID_isRejected() throws Exception
    {
        try
        {
            SecretKeyFactory.getInstance("1.2.840.113549.2.99",
                    JostleProvider.PROVIDER_NAME);
            Assertions.fail("expected NoSuchAlgorithmException for unregistered OID");
        }
        catch (java.security.NoSuchAlgorithmException expected)
        {
            // Good — JCE rejected the unknown OID at lookup time.
        }
    }


    private static char[] randomChars(int n)
    {
        char[] out = new char[n];
        for (int i = 0; i < n; i++)
        {
            out[i] = (char) ('A' + RANDOM.nextInt(26));
        }
        return out;
    }
}
