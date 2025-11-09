package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class ScryptLimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    KdfNI kdfNI = TestNISelector.getKDFNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

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
    public void testSCRYPT_r_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, -1, 10, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("r is negative", iae.getMessage());
        }

    }

    @Test
    public void testSCRYPT_p_negative() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, -1, new byte[1], 0, 1));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("p is negative", iae.getMessage());
        }

    }


    @Test
    public void testSCRYPT_null_output() throws Exception
    {
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(new byte[1], new byte[1], 8, 10, 1, null, 0, 0));
            Assertions.fail();
        } catch (IllegalArgumentException iae)
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
            Assertions.assertEquals("output length is negative", iae.getMessage());
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
            Assertions.assertEquals("output offset and length out of range", iae.getMessage());
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
            Assertions.assertEquals("output offset and length out of range", iae.getMessage());
        }
    }


}
