package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.InvalidKeyException;
import java.security.Security;

public class MacLimitTest
{

    private final MacServiceNI macNI = TestNISelector.getMacServiceNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void makeInstance_macNameNull()
    {
        try
        {
            macNI.allocateMac(null, "cats");
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("name is null", e.getMessage());
        }
    }

    @Test
    public void makeInstance_functionNameNull()
    {
        try
        {
            macNI.allocateMac("HMAC", null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("mac function name is null", e.getMessage());
        }
    }


    @Test
    public void init_keyNull()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, null);
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("key is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void update_inputNull() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, null, 0, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputOffsetNegative() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], -1, 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputLenNegative() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 0, -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void update_inputOutOfRange_1() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 1, 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void update_inputOutOfRange_2() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 0, 2);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_notInitialised_array() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            //macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[32], 0, 32);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_notInitialised_byte() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            //macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, (byte) 1);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void doFinal_outputNull() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, null, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("output is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputOffsetNegative() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputTooSmall() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + mac len is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void doFinal_notInitialised() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            //macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], 1);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void getMacLength_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.getMacLength(ref);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    // macLengthMeta is the keyless counterpart to getMacLength: it reads the
    // length from OpenSSL algorithm metadata (digest output size / cipher
    // block size) and so MUST answer before init, where getMacLength above
    // returns JO_NOT_INITIALIZED. These are the positive contract tests.
    @Test
    public void macLengthMeta_hmac_beforeInit_returnsDigestSize()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            // No engineInit: keyless query must still succeed.
            Assertions.assertEquals(32, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_cmac_beforeInit_returnsBlockSize()
    {
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            // CMAC length == AES block size (16), independent of key length,
            // so it is answerable before a key is supplied.
            Assertions.assertEquals(16, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_hmac_unknownDigest_opensslError()
    {
        long ref = macNI.allocateMac("HMAC", "NOT-A-REAL-DIGEST");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.macLengthMeta(ref);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:") && e.getMessage().contains("NOT-A-REAL-DIGEST"), e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void reset_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.reset(ref);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void reset_nullRef()
    {
        // Both backends silently return JO_SUCCESS for the spurious-reset case;
        // no exception expected.
        macNI.reset(0L);
    }


    @Test
    public void makeInstance_unknownAlgorithm()
    {
        try
        {
            macNI.allocateMac("ZZZZZZZ", "SHA-256");
            Assertions.fail();
        }
        catch (OpenSSLException ignored)
        {
            // EVP_MAC_fetch fails -> JO_OPENSSL_ERROR -> OpenSSLException.
            // Message text is OpenSSL-version-dependent so we don't assert on it.
        }
    }


    @Test
    public void cmac_unknownCipher() throws Exception
    {
        long ref = macNI.allocateMac("CMAC", "des-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void cmac_invalidKeyLen()
    {
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[17]);
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("invalid key length for mac type", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void init_reInitDifferentKey() throws Exception
    {
        // Exercises mac_init's alias-safe re-init: free-old then alloc-new used to be
        // the order, which would corrupt the key if the caller happened to alias mctx->key.
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineInit(ref, new byte[32]);
            macNI.engineInit(ref, new byte[64]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void init_emptyKey() throws Exception
    {
        // Native layer can accept zero len keys, SecretKeySpec will not,
        // however.
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[0]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


}
