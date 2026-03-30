package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

public class MacLimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable();
    }

    private final MacServiceNI macNI = TestNISelector.getMacServiceNI();

    @Test
    public void makeInstance_digestNameNull()
    {
        Assertions.assertThrows(NullPointerException.class, () -> macNI.allocateMac("HMAC", null));
    }

    @Test
    public void init_keyNull() {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, null);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("key is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputNull() {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, null, 0, 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputOffsetNegative() {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], -1, 1);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputLenNegative() {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 0, -1);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("input length is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputNull() {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, null, 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("output is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputOffsetNegative() {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], -1);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputTooSmall() {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], 0);
            Assertions.fail();
        }
        catch (Exception e)
        {
            Assertions.assertEquals("output too small", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }
}
