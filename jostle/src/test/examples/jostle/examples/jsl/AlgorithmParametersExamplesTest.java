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
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Algorithm parameters: the ASN.1 encoding of a cipher's IV or nonce, a curve, or a signature's settings,
 * as they travel in CMS, PKCS#8 or X.509. Encode with `getEncoded()`, decode with `init(byte[])`, and read
 * the spec back with `getParameterSpec`.
 */
public class AlgorithmParametersExamplesTest
        extends JslExamples
{
    /**
     * A cipher reports its parameters after `init`; encode them to send with the ciphertext, and rebuild them
     * on the other side to initialise the decrypting cipher.
     */
    @Test
    public void gcmParametersFromACipher()
            throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, Hex.decode("cafebabefacedbaddecaf888")));
        byte[] encoded = enc.getParameters().getEncoded();

        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", "JSL");
        params.init(encoded);
        GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertEquals(128, spec.getTLen());
        Assertions.assertEquals("cafebabefacedbaddecaf888", Hex.toHexString(spec.getIV()));
    }

    /**
     * The IV parameters of the block ciphers, and the nonce parameters of CCM and ChaCha20-Poly1305: build
     * from a spec, encode, decode into a fresh instance, and read the same IV back.
     */
    @Test
    public void ivParametersRoundTrip()
            throws Exception
    {
        String[] names = {"AES", "ARIA", "CAMELLIA", "SM4", "DESEDE", "CCM", "CHACHA20-POLY1305"};
        int[] ivBytes = {16, 16, 16, 16, 8, 12, 12};
        for (int i = 0; i < names.length; i++)
        {
            byte[] iv = new byte[ivBytes[i]];
            iv[0] = 42;
            AlgorithmParameters params = AlgorithmParameters.getInstance(names[i], "JSL");
            params.init(new IvParameterSpec(iv));
            AlgorithmParameters decoded = AlgorithmParameters.getInstance(names[i], "JSL");
            decoded.init(params.getEncoded());
            Assertions.assertArrayEquals(iv, decoded.getParameterSpec(IvParameterSpec.class).getIV(), names[i]);
        }
    }

    /**
     * EC parameters from a curve name: `getParameterSpec(ECParameterSpec.class)` gives the full curve
     * definition, and the encoding is the named-curve OID.
     */
    @Test
    public void ecNamedCurve()
            throws Exception
    {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "JSL");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
        Assertions.assertEquals(256, curve.getOrder().bitLength());
        // 06 08 = OID 1.2.840.10045.3.1.7
        Assertions.assertEquals("06082a8648ce3d030107", Hex.toHexString(params.getEncoded()));
    }

    /**
     * RSASSA-PSS parameters, the form a PSS signature's AlgorithmIdentifier carries: digest, mask generation,
     * salt length and trailer field.
     */
    @Test
    public void rsaPssParameters()
            throws Exception
    {
        PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        params.init(pss);
        AlgorithmParameters decoded = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
        decoded.init(params.getEncoded());
        PSSParameterSpec back = decoded.getParameterSpec(PSSParameterSpec.class);
        Assertions.assertEquals(32, back.getSaltLength());
        Assertions.assertEquals("SHA-256", back.getDigestAlgorithm());
    }
}
