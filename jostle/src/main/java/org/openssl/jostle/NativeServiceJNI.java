/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle;

public class NativeServiceJNI implements NativeServiceNI
{
    public boolean isNativeAvailable()
    {
        return nativeAvailable();
    }

    public String getOpenSSLVersion()
    {
        return openSSLVersion();
    }

    private static native boolean nativeAvailable();

    private static native String openSSLVersion();


}
