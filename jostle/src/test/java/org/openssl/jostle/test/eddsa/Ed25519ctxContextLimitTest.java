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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.ContextParameterSpec;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

/**
 * ED25519CTX needs a non-empty context (RFC 8032 says it SHOULD NOT be empty, and OpenSSL refuses to sign without
 * one). Init stays permissive so the context may be set before or after it, the JCA order this provider supports;
 * the first update, sign or verify with no context, or an empty one, is refused with a SignatureException naming the
 * requirement. With a context set in either order it signs and verifies, and the context is bound into the
 * signature. BouncyCastle registers no Ed25519ctx, so the controls are plain ED25519 on either side of the change.
 */
public class Ed25519ctxContextLimitTest
{
    public static final String REFUSAL = "Ed25519ctx requires a non-empty context: call "
            + "setParameter(ContextParameterSpec) before update";

    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void noContextIsRefusedAtTheFirstOperation() throws Exception
    {
        assertRefusedWithoutContext(JSL, null);
    }

    @Test
    public void emptyContextIsRefusedAtTheFirstOperation() throws Exception
    {
        assertRefusedWithoutContext(JSL, new ContextParameterSpec(new byte[0]));
    }

    @Test
    public void contextSetBeforeOrAfterInitSignsAndVerifies() throws Exception
    {
        assertSignsWithContext(JSL);
    }

    @Test
    public void clearingTheContextAfterInitIsRefusedAtTheNextOperation() throws Exception
    {
        assertClearingRefused(JSL);
    }

    @Test
    public void plainEd25519IsUnchanged() throws Exception
    {
        assertPlainEd25519Unchanged(JSL);
    }

    /**
     * {@code spec} null means no setParameter at all; otherwise it is set before init. Init succeeds on both
     * sides; update, sign with no update, and verify are each refused with the pinned message.
     */
    public static void assertRefusedWithoutContext(String provider, ContextParameterSpec spec) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", provider).generateKeyPair();
        String label = spec == null ? "no context" : "empty context";

        Signature signer = Signature.getInstance("ED25519CTX", provider);
        if (spec != null)
        {
            signer.setParameter(spec);
        }
        signer.initSign(kp.getPrivate());
        assertRefused(() -> signer.update(new byte[]{1}), label + " update");
        assertRefused(() -> signer.update((byte) 1), label + " single-byte update");
        assertRefused(signer::sign, label + " sign");

        Signature verifier = Signature.getInstance("ED25519CTX", provider);
        if (spec != null)
        {
            verifier.setParameter(spec);
        }
        verifier.initVerify(kp.getPublic());
        assertRefused(() -> verifier.verify(new byte[64]), label + " verify");
    }

    /**
     * A random context at lengths spread over 1 to 255 bytes, both ends included, set before init for some lengths
     * and after it for others: the signature verifies under that context, and not under another context or over
     * another message.
     */
    public static void assertSignsWithContext(String provider) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", provider).generateKeyPair();
        boolean afterInit = false;
        for (int len : new int[]{1, 2, 3, 32, 64, 128, 254, 255})
        {
            afterInit = !afterInit;
            byte[] ctx = new byte[len];
            RANDOM.nextBytes(ctx);
            byte[] msg = new byte[1 + RANDOM.nextInt(200)];
            RANDOM.nextBytes(msg);
            String label = "context length " + len + (afterInit ? ", set after init" : ", set before init");

            Signature signer = Signature.getInstance("ED25519CTX", provider);
            if (afterInit)
            {
                signer.initSign(kp.getPrivate());
                signer.setParameter(new ContextParameterSpec(ctx));
            }
            else
            {
                signer.setParameter(new ContextParameterSpec(ctx));
                signer.initSign(kp.getPrivate());
            }
            signer.update(msg);
            byte[] sig = signer.sign();

            Assertions.assertTrue(verify(provider, kp, ctx, msg, sig, afterInit), label);
            byte[] otherCtx = ctx.clone();
            otherCtx[0] ^= 1;
            Assertions.assertFalse(verify(provider, kp, otherCtx, msg, sig, afterInit), label + ", other context");
            byte[] otherMsg = msg.clone();
            otherMsg[0] ^= 1;
            Assertions.assertFalse(verify(provider, kp, ctx, otherMsg, sig, afterInit), label + ", other message");
        }
    }

    /**
     * Resetting the context with setParameter(null) after init leaves the signer initialised and without a
     * context, so its next operation is refused like any other.
     */
    public static void assertClearingRefused(String provider) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", provider).generateKeyPair();
        Signature signer = Signature.getInstance("ED25519CTX", provider);
        signer.setParameter(new ContextParameterSpec(new byte[]{1}));
        signer.initSign(kp.getPrivate());
        signer.setParameter(null);
        assertRefused(() -> signer.update(new byte[]{1}), "after clearing");
    }

    /**
     * Plain ED25519 still signs with no context and still refuses one, at init.
     */
    public static void assertPlainEd25519Unchanged(String provider) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ED25519", provider).generateKeyPair();
        byte[] msg = new byte[64];
        RANDOM.nextBytes(msg);
        Signature signer = Signature.getInstance("ED25519", provider);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance("ED25519", provider);
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        Assertions.assertTrue(verifier.verify(sig));

        Signature withCtx = Signature.getInstance("ED25519", provider);
        withCtx.setParameter(new ContextParameterSpec(new byte[]{1}));
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> withCtx.initSign(kp.getPrivate()));
        Assertions.assertEquals("ED25519 does not accept a context parameter", e.getMessage());
    }

    private static void assertRefused(Executable op, String label)
    {
        SignatureException e = Assertions.assertThrows(SignatureException.class, op, label);
        Assertions.assertEquals(REFUSAL, e.getMessage(), label);
    }

    private static boolean verify(String provider, KeyPair kp, byte[] ctx, byte[] msg, byte[] sig, boolean afterInit)
            throws Exception
    {
        Signature verifier = Signature.getInstance("ED25519CTX", provider);
        if (afterInit)
        {
            verifier.initVerify(kp.getPublic());
            verifier.setParameter(new ContextParameterSpec(ctx));
        }
        else
        {
            verifier.setParameter(new ContextParameterSpec(ctx));
            verifier.initVerify(kp.getPublic());
        }
        verifier.update(msg);
        return verifier.verify(sig);
    }
}
