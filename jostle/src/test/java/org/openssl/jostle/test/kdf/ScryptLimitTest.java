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
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.security.Security;

public class ScryptLimitTest
{

    MemoryHardKdfNI kdfNI = TestNISelector.getMemoryHardKDFNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void testSCRYPT_null_password() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(null, new byte[1], 8, 10, 1, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("password is null", iae.getMessage());
        }

    }

    @Test
    public void testSCRYPT_null_salt() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], null, 8, 10, 1, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("salt is null", iae.getMessage());
        }

    }

    @Test
    public void testSCRYPT_empty_salt() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[0], 8, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("salt is empty", iae.getMessage());
        }

    }

    @Test
    public void testSCRYPT_n_too_small() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 1, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("n is less than 2", iae.getMessage());
        }

        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 0, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("n is less than 2", iae.getMessage());
        }

        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], -1, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("n is less than 2", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_n_not_pow2() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 3, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("n not power of 2", iae.getMessage());
        }

        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 5, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("n not power of 2", iae.getMessage());
        }

        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 65537, 10, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("n not power of 2", iae.getMessage());
        }
    }


    @Test
    public void testSCRYPT_r_too_small() throws Exception
    {
        // RFC 7914 requires r >= 1; 0, -1 and MIN_VALUE are all rejected typed.
        for (int r : new int[]{0, -1, Integer.MIN_VALUE})
        {
            try
            {
                kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, r, 10, new byte[1], 0, 1));
                Assertions.fail("r=" + r);
            } catch (IllegalArgumentException iae)
            {
                Assertions.assertEquals("r is less than 1", iae.getMessage());
            }
        }
    }

    @Test
    public void testSCRYPT_p_too_small() throws Exception
    {
        // RFC 7914 requires p >= 1; 0, -1 and MIN_VALUE are all rejected typed.
        for (int p : new int[]{0, -1, Integer.MIN_VALUE})
        {
            try
            {
                kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, p, new byte[1], 0, 1));
                Assertions.fail("p=" + p);
            } catch (IllegalArgumentException iae)
            {
                Assertions.assertEquals("p is less than 1", iae.getMessage());
            }
        }
    }


    @Test
    public void testSCRYPT_null_output() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, null, 0, 0));
            Assertions.fail();
        } catch (NullPointerException iae)
        {
            Assertions.assertEquals("output is null", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_offset_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], -1, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }

    }

    @Test
    public void testSCRYPT_output_length_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 0, -1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_range_past_end_1() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 0, 11));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_range_past_end_2() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 1, 10));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset + length is out of range", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_offset_minValue() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], Integer.MIN_VALUE, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output offset is negative", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_length_minValue() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, new byte[10], 0, Integer.MIN_VALUE));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("output len negative", iae.getMessage());
        }
    }

    @Test
    public void testSCRYPT_output_range_atEnd_accepted() throws Exception
    {
        // Positive companion to the past-end probes: offset + len == size is
        // exactly in range, proving the boundary sits past the end (not one
        // byte earlier). A real derive since EVP_KDF_derive rejects keylen == 0.
        int code = kdfNI.scrypt(new byte[1], new byte[1], 2, 8, 1, new byte[42], 10, 32);
        Assertions.assertEquals(0, code);
    }

    @Test
    public void testSCRYPT_empty_password_accepted() throws Exception
    {
        // An empty (non-null) password is valid and must derive on BOTH bridges
        // — the FFI path marshals an empty array to a non-NULL 1-byte segment so
        // the bridge sees "present but empty", not JO_KDF_PASSWORD_NULL. Run
        // under integrationTest25JNI and integrationTest25FFI for parity.
        int code = kdfNI.scrypt(new byte[0], new byte[1], 2, 8, 1, new byte[16], 0, 16);
        Assertions.assertEquals(0, code);
    }
}
