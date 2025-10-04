/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.test;

public class TestFailedException 
    extends RuntimeException
{
    private final TestResult _result;
    
    public TestFailedException(
        TestResult result)
    {
        _result = result;
    }
    
    public TestResult getResult()
    {
        return _result;
    }
}
