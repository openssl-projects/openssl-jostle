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

import org.openssl.jostle.util.Strings;

public class SimpleTestResult implements TestResult
{
    private static final String SEPARATOR = Strings.lineSeparator();

    private final boolean             success;
    private final String              message;
    private Throwable           exception;

    public SimpleTestResult(boolean success, String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(boolean success, String message, Throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(
        Test test, 
        String message)
    {
        return new SimpleTestResult(true, test.getName() + ": " + message);
    }

    public static TestResult failed(
        Test test, 
        String message)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message);
    }
    
    public static TestResult failed(
        Test test, 
        String message, 
        Throwable t)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message, t);
    }
    
    public static TestResult failed(
        Test test, 
        String message, 
        Object expected, 
        Object found)
    {
        return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }
    
    public static String failedMessage(String algorithm, String testName, String expected,
            String actual)
    {
        String sb = algorithm + " failing " + testName +
                SEPARATOR + "    expected: " + expected +
                SEPARATOR + "    got     : " + actual;

        return sb;
    }

    public boolean isSuccessful()
    {
        return success;
    }

    public String toString()
    {
        return message;
    }

    public Throwable getException()
    {
        return exception;
    }
}
