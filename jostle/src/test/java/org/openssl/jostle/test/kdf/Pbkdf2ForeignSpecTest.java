/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.kdf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * MT-81: the un-forced PBKDF2 factory must not silently default a PRF it cannot
 * read.
 *
 * <h2>The defect</h2>
 *
 * <p>A {@link PBEKeySpec} SUBCLASS may carry a PRF where this factory cannot see
 * it — bc-java's {@code org.bouncycastle.jcajce.spec.PBKDF2KeySpec} holds an
 * {@code AlgorithmIdentifier}. Falling through to the SHA-1 default then derives
 * the wrong key for a caller who asked for SHA-256, and they learn only at a
 * padding failure. Measured before the fix: bc's spec with HMAC-SHA256 produced
 * the SHA-1 bytes, identical to HMAC-SHA1 and to SunJCE's HmacSHA1, while the
 * correct answer is SunJCE's HmacSHA256.
 *
 * <p>The bare-name half predates the OID alias; adding the alias only widened it
 * onto the path PBES2 and PKCS#8 resolve by, replacing a loud
 * {@code NoSuchAlgorithmException}. Both halves are covered here.
 *
 * <h2>Why refusing is not the same as defaulting</h2>
 *
 * <p>An EXACT {@code PBEKeySpec} genuinely carries no PRF, so SHA-1 is RFC 8018
 * A.2's absent-prf default and stays — BouncyCastle's own bare PBKDF2 agrees,
 * measured. A subclass carries one this factory cannot read, and ignoring it is
 * ignoring a parameter rather than applying a default.
 */
public class Pbkdf2ForeignSpecTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String PBKDF2_OID = "1.2.840.113549.1.5.12";

    private static final char[] PASSWORD = "password".toCharArray();
    private static final byte[] SALT = new byte[16];
    private static final int ITERATIONS = 1000;
    private static final int KEY_BITS = 256;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * An anonymous subclass stands in for every foreign spec: it carries nothing
     * this factory can read, which is precisely the condition being refused.
     * Using a local subclass rather than bc-java's keeps the test independent of
     * the bcprov version while testing the same property.
     */
    @Test
    public void aForeignSpecSubclassIsRefusedOnBothSpellings() throws Exception
    {
        for (String name : new String[]{"PBKDF2", PBKDF2_OID})
        {
            PBEKeySpec foreign = new PBEKeySpec(PASSWORD, SALT, ITERATIONS, KEY_BITS) { };
            InvalidKeySpecException ex = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> SecretKeyFactory.getInstance(name, JSL).generateSecret(foreign),
                    name + ": a spec carrying an unreadable PRF must be refused, not defaulted");
            Assertions.assertTrue(ex.getMessage().contains("PBKDF2withHMAC"),
                    name + ": the refusal must name the factories that can do it; got: "
                            + ex.getMessage());
        }
    }

    /** RFC 8018 A.2: an exact PBEKeySpec carries no PRF, so SHA-1 stands. */
    @Test
    public void anExactPbeKeySpecKeepsTheSha1DefaultAndMatchesTheReferences() throws Exception
    {
        byte[] ours = derive(SecretKeyFactory.getInstance("PBKDF2", JSL));
        byte[] sun = derive(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"));
        byte[] bc = derive(SecretKeyFactory.getInstance("PBKDF2", "BC"));

        Assertions.assertTrue(Arrays.areEqual(ours, sun),
                "the absent-prf default must be SHA-1, as SunJCE's PBKDF2WithHmacSHA1 computes it");
        Assertions.assertTrue(Arrays.areEqual(ours, bc),
                "and as BouncyCastle's own bare PBKDF2 computes it");
    }

    /** The OID must behave as the bare name for the exact spec too, not merely resolve. */
    @Test
    public void theOidComputesWhatTheBareNameComputes() throws Exception
    {
        Assertions.assertTrue(Arrays.areEqual(
                        derive(SecretKeyFactory.getInstance("PBKDF2", JSL)),
                        derive(SecretKeyFactory.getInstance(PBKDF2_OID, JSL))),
                "the PBKDF2 OID must derive what the named factory derives");
    }

    /**
     * The forced-digest factories keep accepting a foreign subclass and derive
     * their OWN digest. Pinned unchanged and deliberately: that is how a
     * bc-java caller reaches the right PRF once its decryptor resolves
     * PBKDF2withHMAC&lt;digest&gt; by name, so a refusal here would break the
     * other half of the repair.
     */
    @Test
    public void aForcedDigestFactoryStillAcceptsAForeignSpecAndUsesItsOwnDigest() throws Exception
    {
        PBEKeySpec foreign = new PBEKeySpec(PASSWORD, SALT, ITERATIONS, KEY_BITS) { };
        byte[] viaForeign = SecretKeyFactory.getInstance("PBKDF2withHMACSHA256", JSL)
                .generateSecret(foreign).getEncoded();
        byte[] viaExact = derive(SecretKeyFactory.getInstance("PBKDF2withHMACSHA256", JSL));
        byte[] sun = derive(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"));

        Assertions.assertTrue(Arrays.areEqual(viaForeign, viaExact),
                "a named factory's digest comes from its NAME, so a spec it cannot read changes nothing");
        Assertions.assertTrue(Arrays.areEqual(viaForeign, sun),
                "and the result must be the SHA-256 key SunJCE computes");
        Assertions.assertFalse(Arrays.areEqual(viaForeign,
                        derive(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"))),
                "differentiator: SHA-256 and SHA-1 keys must differ, or this cell proves nothing");
    }

    private static byte[] derive(SecretKeyFactory factory) throws Exception
    {
        return factory.generateSecret(
                new PBEKeySpec(PASSWORD, SALT, ITERATIONS, KEY_BITS)).getEncoded();
    }
}
