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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

public class PBKdf2LimitTest
{


    KdfNI kdfNI = TestNISelector.getKDFNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void testPBKDF2_null_password() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(null, new byte[1], 100, "SHA-1", new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("password is null", iae.getMessage());
        }

    }

    @Test
    public void testPBKDF2_null_salt() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], null, 100, "SHA-1", new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("salt is null", iae.getMessage());
        }

    }

    @Test
    public void testPBKDF2_empty_salt() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[0], 100, "SHA-1", new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("salt is empty", iae.getMessage());
        }

    }

    @Test
    public void testPBKDF2_iter_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], -1, "SHA-1", new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("iter is negative", iae.getMessage());
        }

    }

    @Test
    public void testPBKDF2_null_output() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", null, 0, 0));
            Assertions.fail();
        } catch (NullPointerException iae)
        {
            Assertions.assertEquals("output is null", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_offset_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], -1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }

    }

    @Test
    public void testPBKDF2_output_length_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_range_past_end_1() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_range_past_end_2() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 1, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
        }
    }


    @Test
    public void testPBKDF2_null_digest() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, null, new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("unknown digest", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_empty_digest() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "", new byte[10], 0, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("unknown digest", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_unknown_digest() throws Exception
    {
        // Real-failure path: "!" is not a valid digest. OPS_OFFSET_*(x) only
        // applies an offset when its matching flag is set, so caller sees
        // plain OpenSSLException in both OPS and non-OPS builds.
        try
        {
            int code = kdfNI.pbkdf2(new byte[1], new byte[1], 100, "!", new byte[10], 0, 10);
            kdfNI.handleErrorCodes(code);
            Assertions.fail();
        } catch (OpenSSLException osex)
        {
            String message = osex.getMessage();
            Assertions.assertTrue(message.contains("unsupported") && message.contains("! : 0"));
        }
    }

    @Test
    public void testPBKDF2_output_offset_minValue() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], Integer.MIN_VALUE, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_length_minValue() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.pbkdf2(new byte[1], new byte[1], 100, "SHA-1", new byte[10], 0, Integer.MIN_VALUE));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testPBKDF2_output_range_atEnd_accepted() throws Exception
    {
        // Positive companion to the past-end probes: offset + len == size is
        // exactly in range, proving the boundary sits past the end (not one
        // byte earlier). A real derive since EVP_KDF_derive rejects keylen == 0.
        int code = kdfNI.pbkdf2(new byte[10], new byte[1], 1, "SHA-1", new byte[42], 10, 32);
        Assertions.assertEquals(0, code);
    }

    @Test
    public void testPBKDF2_empty_password_accepted() throws Exception
    {
        // An empty (non-null) password is valid and must derive on BOTH bridges
        // — the FFI path marshals an empty array to a non-NULL 1-byte segment so
        // the bridge sees "present but empty", not JO_KDF_PASSWORD_NULL. Run
        // under integrationTest25JNI and integrationTest25FFI for parity.
        int code = kdfNI.pbkdf2(new byte[0], new byte[1], 1, "SHA-1", new byte[16], 0, 16);
        Assertions.assertEquals(0, code);
    }
}
