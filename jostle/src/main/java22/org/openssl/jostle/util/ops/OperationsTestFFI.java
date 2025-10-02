package org.openssl.jostle.util.ops;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Optional;

public class OperationsTestFFI implements OperationsTestNI
{

    private static final SymbolLookup lookup = SymbolLookup.loaderLookup();
    private static final Linker linker = Linker.nativeLinker();

    private static final boolean isOpsTestAvailable;
    private static MemorySegment setOpsFunc = null;
    private static MethodHandle setOpsFuncHandler = null;

    static
    {
        Optional<MemorySegment> func = lookup.find("set_ops_test");
        isOpsTestAvailable = func.isPresent();
        if (isOpsTestAvailable)
        {
            setOpsFunc = func.get();
            setOpsFuncHandler = linker.downcallHandle(setOpsFunc, FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
        }

    }

    public static boolean isIsOpsTestAvailable()
    {
        return isOpsTestAvailable;
    }


    @Override
    public boolean opsTestAvailable()
    {
        return isOpsTestAvailable;
    }

    @Override
    public void setOpsTestFlag(int flag, int value)
    {
        if (!isOpsTestAvailable)
        {
            throw new IllegalStateException("no ops testing available on native side");
        }

        try
        {
            setOpsFuncHandler.invokeExact(flag, value);
        } catch (Throwable e)
        {
            throw new RuntimeException(e);
        }
    }
}
