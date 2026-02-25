package org.openssl.jostle.test.md;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

public class MDInternalOpsTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    MDServiceNI mdNI = TestNISelector.getMDNI();
    OperationsTestNI operationsTestNI = TestNISelector.getOperationsTestNI();

    @Test
    public void testMDdigestLenZero() throws Exception
    {

        try (var a = Arena.ofConfined())
        {

            var seg = a.allocate(1024);
            for (int i = 0; i < seg.byteSize(); i++)
            {
                seg.set(ValueLayout.JAVA_BYTE, (long) i, (byte) 0);
            }

            try
            {
                mdNI.getDigestOutputLen(seg.address());
                Assertions.fail("expected exception");
            } catch (IllegalStateException e)
            {
                Assertions.assertEquals("not initialized", e.getMessage());
            }


        } catch (Throwable t)
        {
            throw new RuntimeException("Error in MD digest operation", t);
        }

    }
}
