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

package org.openssl.jostle.test.eddsa;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.interfaces.EdDSAPrivateKey;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.EdDSAPrivateKeySpec;
import org.openssl.jostle.jcajce.spec.EdDSAPublicKeySpec;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.function.Predicate;

/**
 * Every RFC 8032 section 7 vector through one provider: the key from the secret, the derived public key, the
 * signature bytes, verify, and a verify that fails on a changed message and on a changed context.
 */
public final class Rfc8032VectorCells
{
    private Rfc8032VectorCells()
    {
    }

    /**
     * @param served answers whether the provider serves a signature name; a vector whose name it does not serve
     *               is counted, not run.
     * @return the number of vectors run.
     */
    public static int checkAll(String provider, Predicate<String> served) throws Exception
    {
        int run = 0;
        for (Rfc8032Vectors.Vector v : Rfc8032Vectors.ALL)
        {
            if (!served.test(v.algorithm))
            {
                continue;
            }
            check(provider, v);
            run++;
        }
        return run;
    }

    public static void check(String provider, Rfc8032Vectors.Vector v) throws Exception
    {
        boolean ed448 = v.algorithm.startsWith("Ed448");
        EdDSAParameterSpec params = ed448 ? EdDSAParameterSpec.ED448 : EdDSAParameterSpec.ED25519;
        KeyFactory kf = KeyFactory.getInstance(ed448 ? "Ed448" : "Ed25519", provider);

        PrivateKey priv = kf.generatePrivate(new EdDSAPrivateKeySpec(params, Hex.decode(v.secret), null));
        Assertions.assertEquals(v.publicKey,
                Hex.toHexString(((EdDSAPrivateKey) priv).getPublicKey().getRawPublic()), v.toString());
        PublicKey pub = kf.generatePublic(new EdDSAPublicKeySpec(params, Hex.decode(v.publicKey)));

        byte[] msg = Hex.decode(v.message);
        byte[] ctx = Hex.decode(v.context);

        Signature signer = signature(provider, v.algorithm, ctx);
        signer.initSign(priv);
        signer.update(msg);
        Assertions.assertEquals(v.signature, Hex.toHexString(signer.sign()), v.toString());

        byte[] sig = Hex.decode(v.signature);
        Assertions.assertTrue(verify(provider, v.algorithm, ctx, pub, msg, sig), v.toString());

        byte[] changed = msg.length == 0 ? new byte[]{0} : msg.clone();
        changed[0] ^= 1;
        Assertions.assertFalse(verify(provider, v.algorithm, ctx, pub, changed, sig), v.toString());
        if (ctx.length > 0)
        {
            byte[] otherCtx = ctx.clone();
            otherCtx[0] ^= 1;
            Assertions.assertFalse(verify(provider, v.algorithm, otherCtx, pub, msg, sig), v.toString());
        }
    }

    private static Signature signature(String provider, String algorithm, byte[] ctx) throws Exception
    {
        Signature s = Signature.getInstance(algorithm, provider);
        if (ctx.length > 0)
        {
            s.setParameter(new ContextParameterSpec(ctx));
        }
        return s;
    }

    private static boolean verify(String provider, String algorithm, byte[] ctx, PublicKey pub, byte[] msg,
                                  byte[] sig) throws Exception
    {
        Signature s = signature(provider, algorithm, ctx);
        s.initVerify(pub);
        s.update(msg);
        return s.verify(sig);
    }
}
