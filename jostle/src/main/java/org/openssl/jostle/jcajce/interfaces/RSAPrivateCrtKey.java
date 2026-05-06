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

package org.openssl.jostle.jcajce.interfaces;

/**
 * Jostle private key that exposes the Chinese-Remainder-Theorem
 * components (primes p and q, exponents dP and dQ, qInv coefficient).
 *
 * <p>A key constructed from a non-CRT spec (e.g. from
 * {@link java.security.spec.RSAPrivateKeySpec}) returns {@code null}
 * for each CRT-component getter per the JCA contract.
 */
public interface RSAPrivateCrtKey extends RSAPrivateKey, java.security.interfaces.RSAPrivateCrtKey
{
}
