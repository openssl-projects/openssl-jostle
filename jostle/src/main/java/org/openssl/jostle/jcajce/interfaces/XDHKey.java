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
 * Marker for Jostle's XDH (X25519 / X448) key types. Deliberately does
 * NOT extend {@code java.security.interfaces.XECKey} — that interface is
 * Java 11+, and Jostle's baseline is Java 8. Callers handling keys from
 * multiple providers can dispatch on Jostle-typed XDH keys without
 * pulling in another provider's implementation.
 */
public interface XDHKey extends Key
{
}
