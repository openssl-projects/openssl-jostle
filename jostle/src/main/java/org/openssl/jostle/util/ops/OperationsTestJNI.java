/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.ops;


public class OperationsTestJNI implements OperationsTestNI
{
    private static Boolean opsTestAvailable;



    @Override
    public boolean opsTestAvailable()
    {
        if (opsTestAvailable == null)
        {
            try
            {
                setOpsTestFlag(0    , 0);
                opsTestAvailable = true;
            } catch (UnsatisfiedLinkError e)
            {
                opsTestAvailable = false;
            }
        }
        return opsTestAvailable;
    }

    @Override
    public native void setOpsTestFlag(int flag, int value);


}
