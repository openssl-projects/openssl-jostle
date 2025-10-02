package org.openssl.jostle.util;

@FunctionalInterface
public interface AccessSupplier<T>
{
    T run();
}
