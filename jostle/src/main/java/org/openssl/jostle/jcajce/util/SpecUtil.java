package org.openssl.jostle.jcajce.util;

import org.openssl.jostle.util.AccessSupplier;
import org.openssl.jostle.util.AccessWrapper;

import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;

public class SpecUtil
{
    private static Class[] NO_PARAMS = new Class[0];
    private static Object[] NO_ARGS = new Object[0];

    public static String getNameFrom(final AlgorithmParameterSpec paramSpec)
    {
        return (String) AccessWrapper.doAction(new AccessSupplier<Object>()
        {
            public Object run()
            {
                try
                {
                    Method m = paramSpec.getClass().getMethod("getName", NO_PARAMS);

                    return m.invoke(paramSpec, NO_ARGS);
                } catch (Exception e)
                {
                    // ignore - maybe log?
                }

                return null;
            }
        });
    }

    public static byte[] getContextFrom(final AlgorithmParameterSpec paramSpec)
    {
        return (byte[]) AccessWrapper.doAction(new AccessSupplier<Object>()
        {
            public Object run()
            {
                try
                {
                    Method m = paramSpec.getClass().getMethod("getContext", NO_PARAMS);

                    return m.invoke(paramSpec, NO_ARGS);
                } catch (Exception e)
                {

                    // ignore - maybe log?
                }

                return null;
            }
        });
    }
}
