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

import java.security.PublicKey;

// RSAPublicKey is qualified where the JDK's is meant: jostle's of that name is declared here
public interface RSAPublicKey extends PublicKey, RSAKey, java.security.interfaces.RSAPublicKey
{
}
