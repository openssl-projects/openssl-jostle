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


package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.test.eddsa.Ed25519ctxContextLimitTest;

/**
 * The JSLFIPS twin of {@link Ed25519ctxContextLimitTest}, where the module serves Ed25519ctx. JSLFIPS registers
 * ED25519CTX only when the module implements the Ed25519 key type and the Ed25519ctx signature, so the cells run
 * only where it is registered, and the registration is checked against the module on every module.
 */
public class FIPSEd25519ctxContextLimitTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    private static JostleFIPSProvider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void ed25519ctxRegisteredIffModuleImplementsIt()
    {
        boolean implemented = FIPSTestUtil.moduleServesKeyMgmt("ED25519")
                && FIPSTestUtil.moduleServesSignature("ED25519CTX");
        Assertions.assertEquals(implemented, fips.getService("Signature", "ED25519CTX") != null,
                "JSLFIPS Signature.ED25519CTX registration disagrees with the loaded module");
    }

    @Test
    public void noContextIsRefusedAtTheFirstOperation() throws Exception
    {
        assumeRegistered();
        Ed25519ctxContextLimitTest.assertRefusedWithoutContext(FIPS, null);
    }

    @Test
    public void emptyContextIsRefusedAtTheFirstOperation() throws Exception
    {
        assumeRegistered();
        Ed25519ctxContextLimitTest.assertRefusedWithoutContext(FIPS, new ContextParameterSpec(new byte[0]));
    }

    @Test
    public void contextSetBeforeOrAfterInitSignsAndVerifies() throws Exception
    {
        assumeRegistered();
        Ed25519ctxContextLimitTest.assertSignsWithContext(FIPS);
    }

    @Test
    public void clearingTheContextAfterInitIsRefusedAtTheNextOperation() throws Exception
    {
        assumeRegistered();
        Ed25519ctxContextLimitTest.assertClearingRefused(FIPS);
    }

    private static void assumeRegistered()
    {
        Assumptions.assumeTrue(fips.getService("Signature", "ED25519CTX") != null,
                "the loaded FIPS module does not serve Ed25519ctx");
    }
}
