/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * Runtime exception thrown by NI-level entry points when the loaded
 * OpenSSL provider cannot honour a capability the operation's security
 * contract requires — the fail-loud alternative to running silently
 * without it. Current sources:
 * <ul>
 *   <li>PKCS#1 v1.5 decrypt init when the provider does not implement
 *       the implicit-rejection (Bleichenbacher mitigation) parameter —
 *       the OpenSSL 3.1.x FIPS module predates it
 *       ({@code JO_IMPLICIT_REJECTION_UNAVAILABLE});</li>
 *   <li>DH key agreement with a key that carries no subgroup order q,
 *       which FIPS-validated providers reject at derive-init
 *       ({@code JO_DH_Q_REQUIRED});</li>
 *   <li>DH parameter generation when the provider substitutes an
 *       RFC 7919 named group instead of running the PKCS#3 safe-prime
 *       search ({@code JO_DH_PARAMGEN_SUBSTITUTED});</li>
 *   <li>DSA key / domain-parameter generation when the provider gates it
 *       behind the FIPS "sign-check" indicator — OpenSSL's 3.5+ FIPS module
 *       refuses generation while still importing keys and verifying
 *       signatures ({@code JO_DSA_KEYGEN_UNAVAILABLE}).</li>
 * </ul>
 *
 * <p>Subclasses {@link OpenSSLException} so callers that handle the
 * generic OpenSSL error path keep working without code changes. JCE
 * SPIs translate this at their init boundaries into the JCE-canonical
 * checked exception ({@code InvalidKeyException} for cipher / key
 * agreement init, {@code ProviderException} for parameter generation).
 */
public class ProviderCapabilityException extends OpenSSLException
{
    public ProviderCapabilityException()
    {
    }

    public ProviderCapabilityException(String message)
    {
        super(message);
    }

    public ProviderCapabilityException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public ProviderCapabilityException(Throwable cause)
    {
        super(cause);
    }
}
