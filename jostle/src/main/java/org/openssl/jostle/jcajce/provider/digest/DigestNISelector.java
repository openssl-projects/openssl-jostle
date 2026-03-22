/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.digest;

/**
 * Local selector to avoid touching the global NISelector until native side lands.
 */
final class DigestNISelector
{
    static final DigestNI DigestNI = new DigestNIJNI();
    private DigestNISelector() {}
}
