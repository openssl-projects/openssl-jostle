package org.openssl.jostle.test.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.lang.foreign.*;
import java.security.Security;

public class Asn1InternalTest
{

    @BeforeEach
    public void beforeEach()
    {
        synchronized (JostleProvider.class)
        {
            if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
            {
                Security.addProvider(new JostleProvider());
            }

//            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
//            {
//                Security.addProvider(new BouncyCastleProvider());
//            }
        }
    }


    @Test
    public void decodePublicKey_src_len_overflow() throws Throwable
    {
        Assumptions.assumeTrue(CryptoServicesRegistrar.isNativeAvailable());
        Assumptions.assumeTrue(Loader.isFFI());

        SymbolLookup lookup = SymbolLookup.loaderLookup();
        Linker linker = Linker.nativeLinker();

        //
        // Requires FFI to directly manipulate internal function
        //
        MemorySegment spec = null;
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("asn1_writer_decode_public_key").orElseThrow();
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

            var src = arena.allocate(10);
            var ret_code = arena.allocateFrom(ValueLayout.OfInt.JAVA_INT, 0);

            spec = (MemorySegment) handle.invokeExact(src, Integer.MAX_VALUE + 1L, ret_code);

            int code = ret_code.get(ValueLayout.JAVA_INT, 0);

            Assertions.assertEquals(ErrorCode.JO_INPUT_TOO_LONG_INT32.getCode(), code);

        } finally
        {
            if (spec != null)
            {
                TestNISelector.getSpecNI().dispose(spec.address());
            }
        }


    }

    @Test
    public void decodePrivateKey_src_len_overflow() throws Throwable
    {

        //
        // Requires FFI to directly manipulate internal function
        //

        Assumptions.assumeTrue(CryptoServicesRegistrar.isNativeAvailable());
        Assumptions.assumeTrue(Loader.isFFI());

        SymbolLookup lookup = SymbolLookup.loaderLookup();
        Linker linker = Linker.nativeLinker();


        MemorySegment spec = null;
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("asn1_writer_decode_private_key").orElseThrow();
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

            var src = arena.allocate(10);
            var ret_code = arena.allocateFrom(ValueLayout.OfInt.JAVA_INT, 0);

            spec = (MemorySegment) handle.invokeExact(src, Integer.MAX_VALUE + 1L, ret_code);

            int code = ret_code.get(ValueLayout.JAVA_INT, 0);

            Assertions.assertEquals(ErrorCode.JO_INPUT_TOO_LONG_INT32.getCode(), code);

        } finally
        {
            if (spec != null)
            {
                TestNISelector.getSpecNI().dispose(spec.address());
            }
        }


    }
}
