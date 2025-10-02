/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

enum OSSLMode
{
    //
    // WARNING, these are passed by ordinal value, if you change the order
    // then you MUST also ensure the underlying native interface reflects that
    // change!!
    //
    ECB, CBC, CFB1, CFB8, CFB64, CFB128, CTR, CCM, GCM, OFB, OCB, XTS, WRAP, WRAP_PAD;
}
