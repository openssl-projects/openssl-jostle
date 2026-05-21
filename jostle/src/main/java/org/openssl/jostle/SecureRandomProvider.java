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

    /**
     * Return a SecureRandom instance whose reported security strength
     * is at least {@code strengthBits}. Defaults to {@link #get()} —
     * implementations that can't construct a strength-targeted source
     * (the Java 8 baseline, or a user-set override) leave the
     * resolution to the caller / native RAND gate.
     *
     * <p>The Java 9+ override of {@code ThreadLocalSecureRandomProvider}
     * implements this by constructing a {@code SecureRandom.getInstance("DRBG", DrbgParameters.instantiation(strengthBits, ...))} —
     * letting the post-quantum SPIs satisfy their security-category
     * requirements without an explicit caller-supplied SecureRandom
     * (GH issue #34).
     *
     * @param strengthBits desired minimum strength in bits (typically
     *                     128, 192, or 256).
     * @return a SecureRandom suitable for use at the requested
     *         strength, or the regular default if the provider can't
     *         honour the strength request.
     */
    default SecureRandom get(int strengthBits)
    {
        return get();
    }
}
