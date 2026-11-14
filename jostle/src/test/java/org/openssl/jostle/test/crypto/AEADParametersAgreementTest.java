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
import org.openssl.jostle.jcajce.spec.AEADParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The GCM and CCM AlgorithmParameters take the provider's own AEADParameterSpec as they take a GCMParameterSpec:
 * the same RFC 5084 encoding, equal to BouncyCastle 1.87's for its AEADParameterSpec, and the same spec read back.
 * The encoding carries the nonce and the tag length only, so associated data is not kept, as in BouncyCastle.
 */
public class AEADParametersAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Mode, nonce lengths and tag lengths in bits each mode allows. */
    private static final Object[][] MODES = {
        {"GCM", new int[]{12, 16}, new int[]{96, 104, 112, 120, 128}},
        {"CCM", new int[]{7, 10, 13}, new int[]{32, 48, 64, 80, 96, 112, 128}}};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static byte[] random(int len)
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    /**
     * For every allowed nonce and tag length: our AEADParameterSpec encodes as our GCMParameterSpec and as
     * BouncyCastle's AEADParameterSpec, reads back as itself, and survives getEncoded and init(byte[]).
     */
    @Test
    public void aeadSpecEncodesAsTheGcmSpecAndAsBouncyCastle() throws Exception
    {
        int checked = 0;
        for (Object[] m : MODES)
        {
            String mode = (String) m[0];
            for (int nonceLen : (int[]) m[1])
            {
                for (int bits : (int[]) m[2])
                {
                    byte[] nonce = random(nonceLen);
                    String label = mode + " nonce " + nonceLen + " tag " + bits;

                    AlgorithmParameters viaAead = AlgorithmParameters.getInstance(mode, JSL);
                    viaAead.init(new AEADParameterSpec(nonce, bits));
                    AlgorithmParameters viaGcm = AlgorithmParameters.getInstance(mode, JSL);
                    viaGcm.init(new GCMParameterSpec(bits, nonce));
                    AlgorithmParameters bc = AlgorithmParameters.getInstance(mode, BC);
                    // AEADParameterSpec: BouncyCastle's is qualified, jostle's is imported
                    bc.init(new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, bits));

                    byte[] encoded = viaAead.getEncoded();
                    Assertions.assertArrayEquals(viaGcm.getEncoded(), encoded, label + " against the GCM spec");
                    Assertions.assertArrayEquals(bc.getEncoded(), encoded, label + " against BouncyCastle");

                    AEADParameterSpec back = viaAead.getParameterSpec(AEADParameterSpec.class);
                    Assertions.assertArrayEquals(nonce, back.getNonce(), label);
                    Assertions.assertEquals(bits, back.getMacSizeInBits(), label);

                    AlgorithmParameters decoded = AlgorithmParameters.getInstance(mode, JSL);
                    decoded.init(encoded);
                    AEADParameterSpec again = decoded.getParameterSpec(AEADParameterSpec.class);
                    Assertions.assertArrayEquals(nonce, again.getNonce(), label + " decoded");
                    Assertions.assertEquals(bits, again.getMacSizeInBits(), label + " decoded");
                    checked++;
                }
            }
        }
        Assertions.assertEquals(2 * 5 + 3 * 7, checked, "every mode, nonce and tag length must be driven");
    }

    /** Associated data has no field in the encoding: neither provider keeps it. */
    @Test
    public void associatedDataIsNotKept() throws Exception
    {
        for (Object[] m : MODES)
        {
            String mode = (String) m[0];
            byte[] nonce = random(((int[]) m[1])[0]);
            AlgorithmParameters ours = AlgorithmParameters.getInstance(mode, JSL);
            ours.init(new AEADParameterSpec(nonce, 128, random(5)));
            Assertions.assertNull(ours.getParameterSpec(AEADParameterSpec.class).getAssociatedData(), mode);

            AlgorithmParameters bc = AlgorithmParameters.getInstance(mode, BC);
            // AEADParameterSpec: BouncyCastle's is qualified, jostle's is imported
            bc.init(new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, 128, random(5)));
            Assertions.assertNull(bc.getParameterSpec(org.bouncycastle.jcajce.spec.AEADParameterSpec.class)
                    .getAssociatedData(), mode + " BouncyCastle");
        }
    }

    /**
     * A tag length the mode does not allow is refused with InvalidParameterSpecException, which init declares;
     * BouncyCastle lets a raw IllegalArgumentException out, measured live, so the divergence is pinned in both
     * halves.
     */
    @Test
    public void aTagLengthTheModeDoesNotAllowIsRefused() throws Exception
    {
        Object[][] cells = {{"GCM", 12, 64}, {"GCM", 12, 88}, {"CCM", 13, 72}, {"CCM", 13, 120}};
        for (Object[] c : cells)
        {
            String mode = (String) c[0];
            byte[] nonce = random((Integer) c[1]);
            int bits = (Integer) c[2];
            AlgorithmParameters ours = AlgorithmParameters.getInstance(mode, JSL);
            assertThrows(InvalidParameterSpecException.class, () -> ours.init(new AEADParameterSpec(nonce, bits)),
                    mode + " " + bits);

            AlgorithmParameters bc = AlgorithmParameters.getInstance(mode, BC);
            // AEADParameterSpec: BouncyCastle's is qualified, jostle's is imported
            assertThrows(IllegalArgumentException.class,
                    () -> bc.init(new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, bits)),
                    mode + " " + bits + " BouncyCastle");
        }
    }

    /**
     * CCM used to take an AEADParameterSpec as the IvParameterSpec it extends and keep the default 96-bit tag; the
     * tag length the spec carries is now kept.
     */
    @Test
    public void ccmKeepsTheTagLengthOfAnAeadSpec() throws Exception
    {
        byte[] nonce = random(13);
        AlgorithmParameters ours = AlgorithmParameters.getInstance("CCM", JSL);
        ours.init(new AEADParameterSpec(nonce, 64));
        Assertions.assertEquals(64, ours.getParameterSpec(GCMParameterSpec.class).getTLen());
    }

    /** GCM still serves no IvParameterSpec, so a cipher reading the parameters cannot lose the tag length. */
    @Test
    public void gcmStillServesNoIvParameterSpec() throws Exception
    {
        AlgorithmParameters ours = AlgorithmParameters.getInstance("GCM", JSL);
        ours.init(new AEADParameterSpec(random(12), 96));
        assertThrows(InvalidParameterSpecException.class, () -> ours.getParameterSpec(IvParameterSpec.class));
    }

    /**
     * ChaCha20-Poly1305's parameters carry the nonce only, its tag fixed at 128 bits: an AEADParameterSpec of 128
     * bits is taken, encodes as the nonce alone and reads back as itself; any other tag length is refused rather than
     * dropped. BouncyCastle, measured live, takes any tag length at init and drops it, and does not read an
     * AEADParameterSpec back: that divergence is pinned in both halves.
     */
    @Test
    public void chaCha20Poly1305TakesAnAeadSpecAtItsFixedTagLength() throws Exception
    {
        byte[] nonce = random(12);
        AlgorithmParameters ours = AlgorithmParameters.getInstance("ChaCha20-Poly1305", JSL);
        ours.init(new AEADParameterSpec(nonce, 128));
        AlgorithmParameters viaIv = AlgorithmParameters.getInstance("ChaCha20-Poly1305", JSL);
        viaIv.init(new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(viaIv.getEncoded(), ours.getEncoded());
        AEADParameterSpec back = ours.getParameterSpec(AEADParameterSpec.class);
        Assertions.assertArrayEquals(nonce, back.getNonce());
        Assertions.assertEquals(128, back.getMacSizeInBits());

        AlgorithmParameters refused = AlgorithmParameters.getInstance("ChaCha20-Poly1305", JSL);
        InvalidParameterSpecException e = assertThrows(InvalidParameterSpecException.class,
                () -> refused.init(new AEADParameterSpec(nonce, 96)));
        Assertions.assertEquals("tag length is fixed at 128 bits (got 96)", e.getMessage());

        AlgorithmParameters bc = AlgorithmParameters.getInstance("ChaCha20-Poly1305", BC);
        // AEADParameterSpec: BouncyCastle's is qualified, jostle's is imported
        bc.init(new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, 96));
        Assertions.assertArrayEquals(viaIv.getEncoded(), bc.getEncoded(), "BouncyCastle keeps the nonce only");
        assertThrows(InvalidParameterSpecException.class,
                () -> bc.getParameterSpec(org.bouncycastle.jcajce.spec.AEADParameterSpec.class));
    }

    /** The IV parameters of a mode with no tag refuse an AEADParameterSpec rather than drop its tag length. */
    @Test
    public void ivParametersOfAModeWithNoTagRefuseAnAeadSpec() throws Exception
    {
        for (String name : new String[]{"AES", "SM4"})
        {
            AlgorithmParameters ours = AlgorithmParameters.getInstance(name, JSL);
            assertThrows(InvalidParameterSpecException.class, () -> ours.init(new AEADParameterSpec(random(16), 128)),
                    name);
        }
    }

    /**
     * A GCM cipher initialised from parameters built with a 96-bit AEADParameterSpec encrypts with a 96-bit tag:
     * BouncyCastle, given the same nonce and tag length, produces the same ciphertext and decrypts ours.
     */
    @Test
    public void aCipherInitialisedFromTheParametersUsesTheirTagLength() throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(256);
        SecretKey key = kg.generateKey();
        byte[] nonce = random(12);
        byte[] msg = random(1 + RANDOM.nextInt(200));

        AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", JSL);
        params.init(new AEADParameterSpec(nonce, 96));
        Cipher ours = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        ours.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ct = ours.doFinal(msg);
        Assertions.assertEquals(msg.length + 12, ct.length);

        Cipher bc = Cipher.getInstance("AES/GCM/NoPadding", BC);
        bc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(96, nonce));
        Assertions.assertArrayEquals(bc.doFinal(msg), ct);
        bc.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(96, nonce));
        Assertions.assertArrayEquals(msg, bc.doFinal(ct));
    }
}
