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
    public void testPBEKDF2_null_password() throws Exception
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
    public void testPBEKDF2_null_salt() throws Exception
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
    public void testPBEKDF2_empty_salt() throws Exception
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
    public void testPBEKDF2_iter_negative() throws Exception
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
    public void testPBEKDF2_null_output() throws Exception
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
    public void testPBEKDF2_output_offset_negative() throws Exception
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
    public void testPBEKDF2_output_length_negative() throws Exception
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
    public void testPBEKDF2_output_range_past_end_1() throws Exception
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
    public void testPBEKDF2_output_range_past_end_2() throws Exception
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
    public void testPBEKDF2_null_digest() throws Exception
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
    public void testPBEKDF2_empty_digest() throws Exception
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
    public void testPBEKDF2_unknown_digest() throws Exception
    {
        //
        // Real-failure path: "!" is not a valid digest, so OpenSSL returns
        // unsupported. Per-flag OPS_OFFSET_*(x) macros only encode an offset
        // when the matching OPS flag is actually set, so callers see plain
        // JO_OPENSSL_ERROR (-> OpenSSLException) regardless of whether the
        // OPS build is in use — no offset leakage on real failures.
        //
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


    // Scrypt


    // -- end scrypty


}
