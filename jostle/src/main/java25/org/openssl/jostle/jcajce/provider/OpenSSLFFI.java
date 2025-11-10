package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.FFI;

import java.lang.foreign.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Allow setting of OpenSSL Specific parameters
 */
class OpenSSLFFI implements OpenSSLNI
{
    private static final Logger L = Logger.getLogger("OpenSSL");

    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();


    @Override
    public int setOSSLProviderModule(String provider)
    {
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("set_openssl_module").orElseThrow();
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

            var provName = provider != null ? arena.allocateFrom(provider) : MemorySegment.ofAddress(0);

            return (int) handle.invokeExact(provName);
        } catch (Throwable t)
        {
            L.log(Level.WARNING, "ffi set_openssl_module", t);
            throw new RuntimeException(t.getMessage(), t);
        }

    }

    @Override
    public String getOSSLErrors()
    {
        String result = null;
        try (Arena arena = Arena.ofConfined())
        {
            var func = lookup.find("get_ossl_errors").orElseThrow();
            var len = arena.allocate(ValueLayout.ADDRESS);
            var handle = linker.downcallHandle(func, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

            MemorySegment content = null;

            try
            {
                content = (MemorySegment) handle.invokeExact(len);
                content = content.reinterpret(len.get(ValueLayout.JAVA_LONG, 0));
                result = content.getString(0);
            } catch (RuntimeException e)
            {
                throw e;
            } catch (Throwable t)
            {
                throw new RuntimeException(t.getMessage(), t);
            } finally
            {
                if (content != null)
                {
                    FFI.insecureUnsafeFree(content);
                }
            }
        }
        return result;
    }
}
