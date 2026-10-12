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

package org.openssl.jostle.test.ec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.junit.jupiter.api.Assertions;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * EC key and signature cells shared by the base and FIPS tests; each takes the provider under test by name.
 */
public final class ECKeyCells
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private ECKeyCells()
    {
    }

    private static KeyPair p256(String provider) throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", provider);
        g.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return g.generateKeyPair();
    }

    /** ECPrivateKeySpec with a scalar of zero, n or n+1 is refused typed; 1 and n-1 are accepted. */
    public static void privateScalarOutsideTheOrderIsRefused(String provider) throws Exception
    {
        ECParameterSpec params = ((ECPublicKey) p256(provider).getPublic()).getParams();
        BigInteger n = params.getOrder();
        KeyFactory kf = KeyFactory.getInstance("EC", provider);
        for (BigInteger d : new BigInteger[]{BigInteger.ZERO, n, n.add(BigInteger.ONE)})
        {
            InvalidKeySpecException e = Assertions.assertThrows(InvalidKeySpecException.class,
                    () -> kf.generatePrivate(new ECPrivateKeySpec(d, params)));
            Assertions.assertEquals("scalar is not in [1, n-1]", e.getMessage());
        }
        for (BigInteger d : new BigInteger[]{BigInteger.ONE, n.subtract(BigInteger.ONE)})
        {
            ECPrivateKey k = (ECPrivateKey) kf.generatePrivate(new ECPrivateKeySpec(d, params));
            Assertions.assertEquals(d, k.getS());
        }
    }

    /** Neither half of an EC key pair serialises. */
    public static void keysDoNotSerialise(String provider) throws Exception
    {
        KeyPair kp = p256(provider);
        for (Object key : new Object[]{kp.getPrivate(), kp.getPublic()})
        {
            ObjectOutputStream out = new ObjectOutputStream(new ByteArrayOutputStream());
            Assertions.assertThrows(NotSerializableException.class, () -> out.writeObject(key));
        }
    }

    /** A signature with s replaced by n - s (high S) verifies. */
    public static void highSVerifies(String provider) throws Exception
    {
        KeyPair kp = p256(provider);
        BigInteger n = ((ECPublicKey) kp.getPublic()).getParams().getOrder();
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("SHA256withECDSA", provider);
        signer.initSign(kp.getPrivate(), RANDOM);
        signer.update(msg);
        ASN1Sequence seq = ASN1Sequence.getInstance(signer.sign());
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(n.subtract(s)));
        Signature verifier = Signature.getInstance("SHA256withECDSA", provider);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(new DERSequence(v).getEncoded("DER")));
        msg[0] ^= 1;
        verifier.update(msg);
        Assertions.assertFalse(verifier.verify(new DERSequence(v).getEncoded("DER")));
    }
}
