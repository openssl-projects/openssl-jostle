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

package jostle.examples.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.spec.DSAParameterSpec;

/**
 * Parameter generators in the FIPS module. The module does not generate fresh Diffie-Hellman parameters; it
 * would substitute a named group, so JSLFIPS refuses rather than return something other than what was asked
 * for. Use a named group through `KeyPairGenerator` instead. DSA parameter generation follows DSA key
 * generation: the 3.5.8 module refuses it.
 */
public class FipsAlgorithmParameterGeneratorExamplesTest
        extends FipsExamples
{
    /**
     * DH parameter generation is refused with `ProviderException`; a DH key pair on a named group is the way.
     */
    @Test
    public void dhParametersRefusedUseANamedGroup()
            throws Exception
    {
        AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "JSLFIPS");
        gen.init(2048);
        Assertions.assertThrows(ProviderException.class, gen::generateParameters);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "JSLFIPS");
        kpg.initialize(2048);
        Assertions.assertEquals(2048,
                ((DHPublicKey) kpg.generateKeyPair().getPublic()).getParams().getP().bitLength());
    }

    /**
     * DSA parameters at 2048 or 3072 bits, the sizes the module generates. Where the module refuses DSA
     * generation, as the 3.5.8 module does, `generateParameters` throws `ProviderException` saying so.
     */
    @Test
    public void dsaParameters()
            throws Exception
    {
        AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "JSLFIPS");
        gen.init(2048);
        try
        {
            AlgorithmParameters params = gen.generateParameters();
            Assertions.assertEquals(2048, params.getParameterSpec(DSAParameterSpec.class).getP().bitLength());
        }
        catch (ProviderException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("DSA key generation is not supported"), e.getMessage());
        }
    }
}
