/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.ks;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.JvmProbe;

/**
 * ks_load switches the default lib ctx for the PKCS#12 calls with no _ex form,
 * which is safe only while OSSL_LIB_CTX_set0_default is per thread in the
 * library we link. Measured, not recalled: concurrent loads, digests and
 * stores in a child JVM on the bridge this leg runs, with the operation count
 * as the vacuity floor.
 */
public class KSLibCtxThreadsIntegrationTest
{
    @Test
    public void concurrentLoadsDigestsAndStoresAllSucceed() throws Exception
    {
        new JostleProvider();
        String bridge = Loader.isFFM() ? "ffm" : "jni";
        JvmProbe.Result r = JvmProbe.run(LibCtxThreadsProbe.class,
                JvmProbe.props("org.openssl.jostle.loader.interface", bridge));
        Assertions.assertEquals("0", r.get("failed"), bridge + ": " + r.get("errors"));
        Assertions.assertEquals(15 + 15 + 20000 + 3, Integer.parseInt(r.get("ok")), bridge);
    }
}
