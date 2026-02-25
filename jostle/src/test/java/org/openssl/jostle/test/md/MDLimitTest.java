package org.openssl.jostle.test.md;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class MDLimitTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MDServiceNI mdNI = TestNISelector.getMDNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();


    @Test
    public void allocateDigest_testDigestNameIsNull() throws Exception {
        try
        {
            mdNI.allocateDigest(null, 0);
            Assertions.fail();
        } catch(NullPointerException e) {
            Assertions.assertEquals("name is null", e.getMessage());
        }
    }

    @Test
    public void allocateDigest_testInvalidDigestName() throws Exception
    {
        try
        {
            mdNI.allocateDigest("SHA-255", 0);
        } catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("name not found", e.getMessage());
        }
    }

// updateByte does not
@Test
public void updateBytes_inputNull() throws Exception {
    long ref = mdNI.allocateDigest("SHA256", 0);

    try {
        mdNI.engineUpdate(ref,null,0,0);
        Assertions.fail("Expected NullPointerException");
    } catch (NullPointerException e) {
        Assertions.assertEquals("input is null", e.getMessage());
    } finally {
        if (ref >0) {
            mdNI.dispose(ref);
        }
    }
}

    @Test
    public void updateBytes_inputOffsetNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[0],-1,0);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_inputLenNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[0],0,-1);
            Assertions.fail("");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input len negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_range_1() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[10],0,11);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset + length out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_range_2() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[10],1,10);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset + length out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void updateBytes_range_3() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.engineUpdate(ref,new byte[10],11,21);
            Assertions.fail("Expected NullPointerException");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("input offset + length out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_outputOffsetNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[0],-1,0);
            Assertions.fail("fail");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_outputLenNegative() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[0],0,-1);
            Assertions.fail("");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output len negative", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_outputTooSmall() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[31],0,31);
            Assertions.fail("");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output too small", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_range_1() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[31],0,32);
            Assertions.fail("failed");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset + length out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_range_2() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[32],1,32);
            Assertions.fail("failed");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset + length out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }

    @Test
    public void digest_range_3() throws Exception {
        long ref = mdNI.allocateDigest("SHA256", 0);

        try {
            mdNI.digest(ref,new byte[32],32,64);
            Assertions.fail("failed");
        } catch (IllegalArgumentException e) {
            Assertions.assertEquals("output offset + length out of range", e.getMessage());
        } finally {
            if (ref >0) {
                mdNI.dispose(ref);
            }
        }
    }


}
