package org.openssl.jostle;

import java.lang.foreign.*;

public class FFI
{

    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    /**
     * Returns true if value is one.
     * See: interface/ffi/types.h
     *
     * @param value value
     * @return true if the value is 1 all other values are false.
     */
    public static boolean ffi_bool(byte value)
    {
        return value == 1;
    }

    /**
     * Calls free(ptr) on the passed in address.
     * Do not use this if there is a context specific free for whatever you are doing.
     * The underlying C implementation is null safe.
     *
     * @param addr the pointer you want to call free on.
     */
    public static void insecureUnsafeFree(MemorySegment addr)
    {
        if (addr == null)
        {
            return;
        }

        try
        {
            var func = lookup.find("ffi_free_unsecure_null_safe").orElseThrow();
            var handle = linker.downcallHandle(func,
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
            );
            handle.invokeExact(addr);
        } catch (RuntimeException e)
        {
            throw e;
        } catch (Throwable t)
        {
            throw new RuntimeException(t.getMessage(), t);
        }
    }

}
