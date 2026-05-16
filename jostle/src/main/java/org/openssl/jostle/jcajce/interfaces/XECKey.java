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

import java.security.Key;

/**
 * Marker for Jostle's X25519 / X448 key types (RFC 7748 Montgomery
 * curves, used for key agreement). Sits parallel to
 * {@link java.security.interfaces.XECKey} (Java 11+) so callers that
 * handle keys from multiple providers can dispatch on Jostle-typed
 * keys without picking up other providers' implementations.
 *
 * <p>The Java 8 baseline doesn't have {@code java.security.interfaces.XECKey},
 * so this interface only extends {@link Key}. Java 11+ override copies
 * (when added) can extend {@code java.security.interfaces.XECKey} as
 * well — see the multi-release pattern used by {@code ECKey} and the
 * Edwards-curve interfaces.
 */
public interface XECKey extends Key
{
}
