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

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.FFM;
import org.openssl.jostle.NativeServiceNI;

import java.lang.foreign.*;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

public class NativeServiceFFM implements NativeServiceNI
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
            var funcPtr = lookup.find("JoNative_isAvailable").orElseThrow();
            var linker = Linker.nativeLinker();
            var dch = linker.downcallHandle(funcPtr, FunctionDescriptor.of(ValueLayout.JAVA_INT));
            return (int) dch.invokeExact() == 1;
        }
        catch (Throwable e)
        {
            L.warning("ffm access to isNativeAvailable: " + e.getMessage());
        }
        return false;
    }

    public String getOpenSSLVersion()
    {
        try
        {
            return staticString(lookup.find("JoNative_libraryVersion").orElseThrow());
        }
        catch (Throwable e)
        {
            L.warning("ffm access to JoNative_libraryVersion: " + e.getMessage());
        }
        return "unable to obtain OpenSSL library version";
    }

    public String getOpenSSLBuildVersion()
    {
        try
        {
            return staticString(lookup.find("JoNative_libraryBuildVersion").orElseThrow());
        }
        catch (Throwable e)
        {
            L.warning("ffm access to JoNative_libraryBuildVersion: " + e.getMessage());
        }
        return "unable to obtain OpenSSL build version";
    }

    // The C side returns static storage and its length with the terminator; nothing to free.
    private static String staticString(MemorySegment funcPtr) throws Throwable
    {
        try (Arena a = Arena.ofConfined())
        {
            var linker = Linker.nativeLinker();
            var dch = linker.downcallHandle(funcPtr, FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
            var len = a.allocate(ValueLayout.JAVA_LONG);
            var content = (MemorySegment) dch.invokeExact(len);
            content = content.reinterpret(len.get(ValueLayout.OfLong.JAVA_LONG, 0));
            return content.getString(0, StandardCharsets.UTF_8);
        }
    }

}
