package org.openssl.jostle.test.kdf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class PBKdf2LimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    KdfNI kdfNI = TestNISelector.getKDFNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

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
        } catch (IllegalArgumentException iae)
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
            Assertions.assertEquals("output length is negative", iae.getMessage());
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
            Assertions.assertEquals("output offset and length out of range", iae.getMessage());
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
            Assertions.assertEquals("output offset and length out of range", iae.getMessage());
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
    public void testPBEKDF2_unknown_digest_opsEnabled() throws Exception
    {

        //
        // When OpsTesting is enabled it will return an error code that is offset
        // and an IllegalStateException.
        //

        Assumptions.assumeTrue(operationsTestNI.opsTestAvailable());
        int code = -1;
        try
        {
            //
            // Digest string passed directly to OpenSSL. As a result we will see -1003 if OPS Testing is enabled
            // or an OpenSSLException if OPS Testing is not enabled.
            //
            code = kdfNI.pbkdf2(new byte[1], new byte[1], 100, "!", new byte[10], 0, 10);
            kdfNI.handleErrorCodes(code);
            Assertions.fail();
        } catch (IllegalStateException iae)
        {
            //
            // OPS testing was enabled, we will get a different code because of error code offset
            //
            Assertions.assertEquals(-1003, code);
            String message = TestNISelector.getOpenSSLNI().getOSSLErrors();
            Assertions.assertTrue(message.contains("unsupported") && message.contains("! : 0"));
        }
    }

    @Test
    public void testPBEKDF2_unknown_digest_opsDisabled() throws Exception
    {
        //
        // When ops testing is disabled callers will get an OpenSSLException
        //
        Assumptions.assumeFalse(operationsTestNI.opsTestAvailable());
        int code;
        try
        {
            //
            // Digest string passed directly to OpenSSL. As a result we will see -1003 if OPS Testing is enabled
            // or an OpenSSLException if OPS Testing is not enabled.
            //
            code = kdfNI.pbkdf2(new byte[1], new byte[1], 100, "!", new byte[10], 0, 10);
            kdfNI.handleErrorCodes(code);
            Assertions.fail();
        } catch (OpenSSLException osex)
        {
            //
            // Ops testing was not enabled
            //
            String message = osex.getMessage();
            Assertions.assertTrue(message.contains("unsupported") && message.contains("! : 0"));
        }
    }


    // Scrypt


    // -- end scrypty


}
