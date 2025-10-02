package org.openssl.jostle.util;


/**
 * After java 17 AccessController.doPrivileged is slated for removal.
 * This abstracts that away for 17 and later versions
 */
public class AccessWrapper
{
    public static <T> Object doAction(AccessSupplier<T> pa) throws AccessException
    {
        try
        {
            return pa.run();
        } catch (Throwable t)
        {
            throw new AccessException(t.getMessage(), t);
        }
    }
}
