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
 * Marker for Jostle's DH key types. Sits parallel to
 * {@link javax.crypto.interfaces.DHKey} so callers that handle keys
 * from multiple providers (SunJCE, BC, Jostle) can dispatch on
 * Jostle-typed keys without picking up other providers' implementations.
 */
public interface DHKey extends Key, javax.crypto.interfaces.DHKey
{
}
