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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-63: {@code update()} then {@code doFinal(in,off,len)} must produce what
 * BouncyCastle produces, byte for byte.
 *
 * <p>Every NoPadding BLOCK mode threw {@code IllegalBlockSizeException} on this
 * shape where BC succeeded — 10 registered names, both bridges. The cause was in
 * C: {@code final_size()} counted a retained partial block only on the padded
 * path, so the buffer was sized for this call's input alone.
 *
 * <p>The padded and stream rows are controls: they always agreed, so a fix that
 * broke them would show here rather than in a distant suite.
 */
public class NoPaddingChunkedParityTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /** transformation, key algorithm, key bytes, IV bytes (0 = none), block size. */
    private static final String[][] TABLE = {
            {"AES/ECB/NoPadding", "AES", "16", "0", "16"},
            {"AES/CBC/NoPadding", "AES", "16", "16", "16"},
            {"ARIA/ECB/NoPadding", "ARIA", "16", "0", "16"},
            {"ARIA/CBC/NoPadding", "ARIA", "16", "16", "16"},
            {"CAMELLIA/ECB/NoPadding", "CAMELLIA", "16", "0", "16"},
            {"CAMELLIA/CBC/NoPadding", "CAMELLIA", "16", "16", "16"},
            {"SM4/ECB/NoPadding", "SM4", "16", "0", "16"},
            {"SM4/CBC/NoPadding", "SM4", "16", "16", "16"},
            {"DESede/ECB/NoPadding", "DESede", "24", "0", "8"},
            {"DESede/CBC/NoPadding", "DESede", "24", "8", "8"},
            // Controls that always agreed — a fix that breaks them shows here.
            {"AES/CTR/NoPadding", "AES", "16", "16", "16"},
            {"AES/OFB/NoPadding", "AES", "16", "16", "16"},
            {"AES/CFB/NoPadding", "AES", "16", "16", "16"},
            {"AES/CFB8/NoPadding", "AES", "16", "16", "16"},
            {"AES/ECB/PKCS5Padding", "AES", "16", "0", "16"},
            {"AES/CBC/PKCS5Padding", "AES", "16", "16", "16"},
            {"DESede/CBC/PKCS5Padding", "DESede", "24", "8", "8"},
    };

    /** A name leaving the registry must fail this, not silently shrink the pin. */
    private static final int EXPECTED_ROWS = 17;

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static byte[] chunked(String provider, String xform, String keyAlg,
                                  byte[] key, byte[] iv, byte[] msg, int split) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        if (iv != null)
        {
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keyAlg), new IvParameterSpec(iv));
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keyAlg));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] head = c.update(msg, 0, split);
        if (head != null)
        {
            out.write(head);
        }
        // The three-argument doFinal, deliberately: this is the shape MT-63 broke.
        out.write(c.doFinal(msg, split, msg.length - split));
        return out.toByteArray();
    }

    @Test
    public void chunkedTotalMatchesBouncyCastleByteForByte() throws Exception
    {
        Assertions.assertEquals(EXPECTED_ROWS, TABLE.length,
                "the table changed size — update EXPECTED_ROWS deliberately, so a name "
                        + "dropping out cannot shrink this pin silently");

        SecureRandom sr = new SecureRandom();
        List<String> failures = new ArrayList<String>();

        for (String[] row : TABLE)
        {
            String xform = row[0];
            String keyAlg = row[1];
            byte[] key = new byte[Integer.parseInt(row[2])];
            sr.nextBytes(key);
            int ivLen = Integer.parseInt(row[3]);
            byte[] iv = null;
            if (ivLen > 0)
            {
                iv = new byte[ivLen];
                sr.nextBytes(iv);
            }
            int block = Integer.parseInt(row[4]);
            byte[] msg = new byte[block * 3];
            sr.nextBytes(msg);

            // Split inside a block: the case that retains a partial across update().
            int split = block - 1;
            try
            {
                byte[] ours = chunked(JSL, xform, keyAlg, key, iv, msg, split);
                byte[] theirs = chunked(BC, xform, keyAlg, key, iv, msg, split);
                if (!Arrays.areEqual(ours, theirs))
                {
                    failures.add(xform + ": " + ours.length + "B vs BC " + theirs.length + "B");
                }
            }
            catch (Throwable t)
            {
                failures.add(xform + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        Assertions.assertTrue(failures.isEmpty(),
                "update() then doFinal(in,off,len) must equal BouncyCastle byte for byte:\n  "
                        + String.join("\n  ", failures));
    }
}
