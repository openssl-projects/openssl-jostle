/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.disposal;

/**
 * Instances of this class can return a Runnable that will clean up any native resource
 * that need to be freed when the instance goes to be garbage collected.
 */
public interface Disposable
{
    Runnable getDisposeAction();
}
