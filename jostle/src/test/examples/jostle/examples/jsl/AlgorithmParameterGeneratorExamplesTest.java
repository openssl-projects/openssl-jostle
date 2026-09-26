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
package jostle.examples.jsl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.DHParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.spec.DSAParameterSpec;

/**
 * Parameter generators for finite-field Diffie-Hellman and DSA. The size is the caller's choice: JSL accepts
 * any size OpenSSL will generate, including sizes too small to be safe. Where a named group will do, prefer
 * it; generating DH parameters is slow.
 */
public class AlgorithmParameterGeneratorExamplesTest
        extends JslExamples
{
    /**
     * Generate DSA domain parameters (p, q, g), and read them from the generated `AlgorithmParameters` in
     * the encoding a certificate carries.
     */
    @Test
    public void dsaDomainParameters()
            throws Exception
    {
        AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "JSL");
        gen.init(2048);
        AlgorithmParameters params = gen.generateParameters();
        DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);
        Assertions.assertEquals(2048, spec.getP().bitLength());
        Assertions.assertEquals(256, spec.getQ().bitLength());

        AlgorithmParameters decoded = AlgorithmParameters.getInstance("DSA", "JSL");
        decoded.init(params.getEncoded());
        Assertions.assertEquals(spec.getG(), decoded.getParameterSpec(DSAParameterSpec.class).getG());
    }

    /**
     * Generate Diffie-Hellman parameters: a safe prime p and generator g. 1024 bits keeps the example quick;
     * use 2048 or more.
     */
    @Test
    public void dhParameters()
            throws Exception
    {
        AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "JSL");
        gen.init(1024);
        AlgorithmParameters params = gen.generateParameters();
        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        Assertions.assertEquals(1024, spec.getP().bitLength());

        AlgorithmParameters decoded = AlgorithmParameters.getInstance("DH", "JSL");
        decoded.init(params.getEncoded());
        Assertions.assertEquals(spec.getP(), decoded.getParameterSpec(DHParameterSpec.class).getP());
    }
}
