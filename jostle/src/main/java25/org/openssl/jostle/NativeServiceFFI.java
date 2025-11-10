package org.openssl.jostle;

import java.lang.foreign.*;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

public class NativeServiceFFI implements NativeServiceNI
{

    // NB:
    // Before requesting we use some other logging framework, please consider that
    // a provider is foundational code, and should not force dependencies on its users.
    //
    private static final Logger L = Logger.getLogger("NativeInfo");

    private static SymbolLookup lookup = SymbolLookup.loaderLookup();

    public boolean isNativeAvailable()
    {
        try
        {
            var funcPtr = lookup.find("is_native_available").orElseThrow();
            var linker = Linker.nativeLinker();
            var dch = linker.downcallHandle(funcPtr, FunctionDescriptor.of(ValueLayout.JAVA_BYTE));
            return FFI.ffi_bool((byte) dch.invokeExact());
        } catch (Throwable e)
        {
            L.warning("ffi access to isNativeAvailable: " + e.getMessage());
        }
        return false;
    }

    public String getOpenSSLVersion()
    {
        try (Arena a = Arena.ofConfined())
        {
            SymbolLookup stdLib = SymbolLookup.loaderLookup();
            var funcPtr = stdLib.find("openssl_library_version").orElseThrow();
            var linker = Linker.nativeLinker();
            var dch = linker.downcallHandle(funcPtr, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
            var len = a.allocate(ValueLayout.JAVA_LONG);
            var content = (MemorySegment) dch.invokeExact(len);
            content = content.reinterpret(len.get(ValueLayout.OfLong.JAVA_LONG, 0));
            return content.getString(0, StandardCharsets.UTF_8);
        } catch (Throwable e)
        {
            L.warning("ffi access to isNativeAvailable: " + e.getMessage());
        }
        return "unable to obtain OpenSSL library version";
    }

}
