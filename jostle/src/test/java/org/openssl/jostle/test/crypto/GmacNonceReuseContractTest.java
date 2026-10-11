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

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.mac.MacCells;
import org.openssl.jostle.test.parity.BouncyCastleTranscripts;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AESGMAC gives one tag per init, as BouncyCastle's does: after doFinal or reset the instance refuses until a new
 * init, an init repeating the previous key and nonce is refused, and a new nonce or key works. Each cell drives the
 * same sequence on BouncyCastle and requires the same outcome.
 */
public class GmacNonceReuseContractTest
{
    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void refusesAfterDoFinal() throws Exception
    {
        MacCells.gmacRefusesAfterDoFinal(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void refusesAfterReset() throws Exception
    {
        MacCells.gmacRefusesAfterReset(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void refusesTheSameKeyAndNonce() throws Exception
    {
        MacCells.gmacRefusesTheSameKeyAndNonce(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void keepsThePreviousStreamAfterARefusedReinit() throws Exception
    {
        MacCells.gmacKeepsThePreviousStreamAfterARefusedReinit(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void acceptsABANonces() throws Exception
    {
        MacCells.gmacAcceptsABANonces(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void acceptsTheSameNonceAfterARefusedBadKeyInit() throws Exception
    {
        MacCells.gmacAcceptsTheSameNonceAfterARefusedBadKeyInit(JostleProvider.PROVIDER_NAME);
    }

    @Test
    public void newNonceOrNewKeyEqualsAFreshInstance() throws Exception
    {
        MacCells.gmacNewNonceOrNewKeyEqualsAFreshInstance(JostleProvider.PROVIDER_NAME);
    }

    /**
     * BouncyCastle's refusal type against the transcribed one, so a bcprov change that moves it is noticed rather
     * than followed.
     */
    @Test
    public void bouncyCastleRefusalTypeMatchesTheTranscript() throws Exception
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        Mac m = Mac.getInstance("AESGMAC", "BC");
        m.init(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        m.update(new byte[16]);
        Assertions.assertNotNull(m.doFinal());

        Throwable t = Assertions.assertThrows(Throwable.class, () -> {
            m.update(new byte[16]);
            m.doFinal();
        });
        Assertions.assertEquals(BouncyCastleTranscripts.GMAC_REUSE_REFUSAL_TYPE, t.getClass());
    }
}
