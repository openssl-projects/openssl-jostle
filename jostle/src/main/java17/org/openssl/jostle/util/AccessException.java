package org.openssl.jostle.util;

public class AccessException extends RuntimeException
{
    public AccessException()
    {
    }

    public AccessException(String message)
    {
        super(message);
    }

    public AccessException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public AccessException(Throwable cause)
    {
        super(cause);
    }

    public AccessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
