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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Algorithm parameters in the FIPS module: encode with `getEncoded()`, decode with `init(byte[])`, and read
 * the spec back with `getParameterSpec`.
 */
public class FipsAlgorithmParametersExamplesTest
        extends FipsExamples
{
    /**
     * GCM parameters reported by a cipher, encoded and rebuilt on the other side.
     */
    @Test
    public void gcmParametersFromACipher()
            throws Exception
    {
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSLFIPS");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"),
                new GCMParameterSpec(128, Hex.decode("cafebabefacedbaddecaf888")));
        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", "JSLFIPS");
        params.init(enc.getParameters().getEncoded());
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertEquals(128, spec.getTLen());
        Assertions.assertEquals("cafebabefacedbaddecaf888", Hex.toHexString(spec.getIV()));
    }

    /**
     * IV and nonce parameters for AES, Triple-DES and CCM, round-tripped through their encoding.
     */
    @Test
    public void ivParametersRoundTrip()
            throws Exception
    {
        String[] names = {"AES", "DESEDE", "CCM"};
        int[] ivBytes = {16, 8, 12};
        for (int i = 0; i < names.length; i++)
        {
            if (Security.getProvider("JSLFIPS").getService("AlgorithmParameters", names[i]) == null)
            {
                continue;
            }
            byte[] iv = new byte[ivBytes[i]];
            iv[0] = 42;
            AlgorithmParameters params = AlgorithmParameters.getInstance(names[i], "JSLFIPS");
            params.init(new IvParameterSpec(iv));
            AlgorithmParameters decoded = AlgorithmParameters.getInstance(names[i], "JSLFIPS");
            decoded.init(params.getEncoded());
            Assertions.assertArrayEquals(iv, decoded.getParameterSpec(IvParameterSpec.class).getIV(), names[i]);
        }
    }

    /**
     * EC parameters from a curve name, and RSASSA-PSS parameters as a signature's AlgorithmIdentifier carries
     * them.
     */
    @Test
    public void ecAndPssParameters()
            throws Exception
    {
        AlgorithmParameters ec = AlgorithmParameters.getInstance("EC", "JSLFIPS");
        ec.init(new ECGenParameterSpec("secp384r1"));
        Assertions.assertEquals(384, ec.getParameterSpec(ECParameterSpec.class).getOrder().bitLength());

        AlgorithmParameters pss = AlgorithmParameters.getInstance("RSASSA-PSS", "JSLFIPS");
        pss.init(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        AlgorithmParameters decoded = AlgorithmParameters.getInstance("RSASSA-PSS", "JSLFIPS");
        decoded.init(pss.getEncoded());
        Assertions.assertEquals(32, decoded.getParameterSpec(PSSParameterSpec.class).getSaltLength());
    }

    /**
     * DH and DSA domain parameters, taken from keys and round-tripped through their encoding. The DH key comes
     * from JSLFIPS, whose 2048-bit DH keys use a named group; the DSA key from JSL.
     */
    @Test
    public void dhAndDsaParameters()
            throws Exception
    {
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH", "JSLFIPS");
        dh.initialize(2048);
        DHParameterSpec dhSpec = ((DHPublicKey) dh.generateKeyPair().getPublic()).getParams();
        AlgorithmParameters dhParams = AlgorithmParameters.getInstance("DH", "JSLFIPS");
        dhParams.init(dhSpec);
        AlgorithmParameters dhBack = AlgorithmParameters.getInstance("DH", "JSLFIPS");
        dhBack.init(dhParams.getEncoded());
        Assertions.assertEquals(dhSpec.getP(), dhBack.getParameterSpec(DHParameterSpec.class).getP());

        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA", "JSL");
        dsa.initialize(2048);
        java.security.interfaces.DSAParams dsaSpec = ((DSAPublicKey) dsa.generateKeyPair().getPublic()).getParams();
        AlgorithmParameters dsaParams = AlgorithmParameters.getInstance("DSA", "JSLFIPS");
        dsaParams.init(new DSAParameterSpec(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()));
        AlgorithmParameters dsaBack = AlgorithmParameters.getInstance("DSA", "JSLFIPS");
        dsaBack.init(dsaParams.getEncoded());
        Assertions.assertEquals(dsaSpec.getQ(), dsaBack.getParameterSpec(DSAParameterSpec.class).getQ());
    }
}
