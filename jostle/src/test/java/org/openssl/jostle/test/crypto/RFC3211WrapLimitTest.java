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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.Rfc3211WrapFamilies;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * RFC 3211 §2.3.2 boundaries at the JCE surface.
 *
 * <p>Every cell names the OPERATION its refusal fires at — init, wrap or
 * unwrap — because that is a contract in its own right and the two are not
 * interchangeable: a check deferred from init to wrap is caller-visible.
 *
 * <p>Boundary and one either side throughout. The contract cells in
 * {@code RFC3211WrapTest} assert one representative case each; this class is
 * the systematic sweep.
 */
public class RFC3211WrapLimitTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Refused at INIT: a KEK length the family does not serve. */
    @Test
    public void aKekLengthOffTheSetIsRefusedAtInit() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            for (int len : Rfc3211WrapFamilies.kekProbes(alg))
            {
                boolean valid = Rfc3211WrapFamilies.isValidKek(alg, len);
                byte[] kek = rand(len);
                byte[] iv = rand(Rfc3211WrapFamilies.blockOf(alg));
                String tag = alg + " kek=" + len;

                if (valid)
                {
                    Assertions.assertDoesNotThrow(() -> initWrap(kek, iv, alg),
                            tag + ": a valid KEK length was refused");
                    continue;
                }

                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                        () -> initWrap(kek, iv, alg), tag + ": must be refused at init");
                Assertions.assertTrue(e.getMessage().contains("KEK must be"),
                        tag + ": the refusal does not name the permitted lengths: "
                                + e.getMessage());
            }
        }
    }

    /** Refused at INIT: an IV that is not one block. */
    @Test
    public void anIvLengthOffTheBlockSizeIsRefusedAtInit() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            int block = Rfc3211WrapFamilies.blockOf(alg);
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));

            Assertions.assertDoesNotThrow(() -> initWrap(kek, rand(block), alg),
                    alg + ": a one-block IV was refused");

            for (int len : new int[]{block - 1, block + 1})
            {
                String tag = alg + " iv=" + len;
                InvalidAlgorithmParameterException e = Assertions.assertThrows(
                        InvalidAlgorithmParameterException.class,
                        () -> initWrap(kek, rand(len), alg), tag + ": must be refused at init");
                Assertions.assertTrue(e.getMessage().contains("IV must be"),
                        tag + ": the refusal does not name the required length: " + e.getMessage());
            }
        }
    }

    /** Refused at WRAP: the CEK length is encoded in one byte. */
    @Test
    public void aCekLengthOutsideOneByteIsRefusedAtWrap() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
            byte[] iv = rand(Rfc3211WrapFamilies.blockOf(alg));

            for (int len : new int[]{1, 2, 254, 255})
            {
                Cipher c = initWrap(kek, iv, alg);
                Assertions.assertNotNull(c.wrap(new SecretKeySpec(rand(len), "RAW")),
                        alg + " cek=" + len + ": a valid CEK length was refused");
            }

            // A zero-length SecretKeySpec cannot be built — the JDK refuses it
            // in the constructor — so an empty CEK reaches the SPI only through
            // a key that reports one.
            Cipher empty = initWrap(kek, iv, alg);
            IllegalBlockSizeException zero = Assertions.assertThrows(
                    IllegalBlockSizeException.class,
                    () -> empty.wrap(new RawKey(new byte[0])),
                    alg + " cek=0: an empty CEK must be refused at wrap");
            Assertions.assertTrue(zero.getMessage().contains("1..255"),
                    alg + ": the empty-CEK refusal does not name the permitted range: "
                            + zero.getMessage());

            Cipher none = initWrap(kek, iv, alg);
            InvalidKeyException noEnc = Assertions.assertThrows(InvalidKeyException.class,
                    () -> none.wrap(new RawKey(null)),
                    alg + ": a key with no encoding must be refused at wrap");
            Assertions.assertEquals("key has no encoding", noEnc.getMessage(),
                    alg + ": the no-encoding message has moved");

            Cipher over = initWrap(kek, iv, alg);
            IllegalBlockSizeException e = Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> over.wrap(new SecretKeySpec(rand(256), "RAW")),
                    alg + " cek=256: must be refused at wrap");
            Assertions.assertTrue(e.getMessage().contains("1..255"),
                    alg + ": the refusal does not name the permitted range: " + e.getMessage());
        }
    }

    /** Refused at UNWRAP: fewer than two blocks, and not a whole number of them. */
    @Test
    public void aWrappedLengthBelowTwoBlocksOrOffTheBlockIsRefusedAtUnwrap() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            int block = Rfc3211WrapFamilies.blockOf(alg);
            byte[] kek = rand(Rfc3211WrapFamilies.anyValidKek(alg));
            byte[] iv = rand(Rfc3211WrapFamilies.blockOf(alg));

            for (int len : new int[]{0, block, block + 1, 2 * block - 1})
            {
                String tag = alg + " wrapped=" + len;
                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                        () -> unwrap(kek, iv, alg, new byte[len]),
                        tag + ": must be refused at unwrap");
                Assertions.assertEquals("input too short", e.getMessage(),
                        tag + ": the refusal message has moved");
            }

            InvalidKeyException nullBlob = Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(kek, iv, alg, null),
                    alg + ": a null wrapped key must be refused at unwrap");
            Assertions.assertEquals("wrapped key is null", nullBlob.getMessage(),
                    alg + ": the null-blob message has moved");

            // Two whole blocks is the smallest shape the construction permits,
            // so it must fail the integrity check rather than the length one.
            InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                    () -> unwrap(kek, iv, alg, new byte[2 * block]),
                    alg + ": two blocks of zeroes must reach the integrity check");
            Assertions.assertEquals("wrapped key corrupted", e.getMessage(),
                    alg + ": two blocks were refused on length, not on integrity");
        }
    }

    /** Refused at INIT: a null key, and unwrap with no parameters. */
    @Test
    public void aNullKeyAndAMissingIvAreRefusedAtInit() throws Exception
    {
        for (String alg : Rfc3211WrapFamilies.registeredNames())
        {
            byte[] iv = rand(Rfc3211WrapFamilies.blockOf(alg));

            InvalidKeyException nullKey = Assertions.assertThrows(InvalidKeyException.class,
                    () -> initWrapWithKey(null, iv, alg), alg + ": a null key must be refused");
            Assertions.assertEquals("key is null", nullKey.getMessage(),
                    alg + ": the null-key message has moved");

            InvalidKeyException noIv = Assertions.assertThrows(InvalidKeyException.class,
                    () ->
                    {
                        Cipher c = Cipher.getInstance(alg, JSL);
                        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(rand(Rfc3211WrapFamilies.anyValidKek(alg)), alg));
                    },
                    alg + ": unwrap without an IV must be refused");
            Assertions.assertTrue(noIv.getMessage().contains("IvParameterSpec"),
                    alg + ": the missing-IV refusal does not name what is required: "
                            + noIv.getMessage());
        }
    }

    // ------------------------------------------------------------------

    private static byte[] rand(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static Cipher initWrap(byte[] kek, byte[] iv, String alg) throws Exception
    {
        return initWrapWithKey(new SecretKeySpec(kek, alg), iv, alg);
    }

    private static Cipher initWrapWithKey(Key key, byte[] iv, String alg) throws Exception
    {
        Cipher c = Cipher.getInstance(alg, JSL);
        c.init(Cipher.WRAP_MODE, key, new IvParameterSpec(iv));
        return c;
    }

    private static byte[] unwrap(byte[] kek, byte[] iv, String alg, byte[] blob) throws Exception
    {
        Cipher c = Cipher.getInstance(alg, JSL);
        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, alg), new IvParameterSpec(iv));
        return c.unwrap(blob, "RAW", Cipher.SECRET_KEY).getEncoded();
    }

    /** A key that reports exactly what the test needs the SPI to see. */
    private static final class RawKey implements javax.crypto.SecretKey
    {
        private final byte[] encoded;

        private RawKey(byte[] encoded)
        {
            this.encoded = encoded;
        }

        public String getAlgorithm()
        {
            return "RAW";
        }

        public String getFormat()
        {
            return "RAW";
        }

        public byte[] getEncoded()
        {
            return encoded;
        }
    }
}
