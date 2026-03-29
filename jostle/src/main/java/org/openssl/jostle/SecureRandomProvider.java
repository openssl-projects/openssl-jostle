package org.openssl.jostle;

import java.security.SecureRandom;

/**
 * Source provider for SecureRandom implementations.
 */
public interface SecureRandomProvider
{
    /**
     * Return a SecureRandom instance.
     * @return a SecureRandom
     */
    SecureRandom get();
}
