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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.blockcipher.AESBlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-65: the array-returning {@code doFinal} must report an INTERNAL sizing miss
 * as an internal defect, not as a caller block-size error.
 *
 * <h2>What the branch is</h2>
 *
 * <p>{@code BlockCipherSpi.engineDoFinal(byte[],int,int)} allocates its OWN
 * buffer from {@code getFinalSize} and hands it to the five-argument form. A
 * {@code ShortBufferException} from that call therefore cannot be caller data -
 * the caller supplied no buffer - so it can only mean we mis-sized our own.
 * Reporting that as {@code IllegalBlockSizeException} says the CALLER's data was
 * misaligned, which is what made MT-63 read as a block-size rule rather than the
 * sizing bug it was.
 *
 * <h2>Why the fault must be an INCONSISTENT lie, not a consistent one</h2>
 *
 * <p>This is the part that decides whether the test measures anything. The
 * five-argument form calls {@code getFinalSize} AGAIN and compares
 * {@code outputOffset + k > output.length}. So a decorator that under-reports on
 * EVERY call makes both sides agree - the buffer is short and the check thinks
 * it is exactly right - and NO {@code ShortBufferException} is raised. The test
 * would pass while exercising nothing.
 *
 * <p>{@link ShortReportingNi} therefore under-reports on its FIRST call only and
 * tells the truth afterwards, which is precisely the shape of the real defect:
 * the ALLOCATION used a wrong size and the CHECK used the right one.
 */
public class BlockCipherInternalSizingTest
{
    /**
     * Constructing an SPI directly does NOT load the native libraries - the
     * Loader runs when a provider is instantiated. Without this the whole class
     * fails with {@code UnsatisfiedLinkError}, and because the fault arrives as
     * a THROWABLE inside the measured call it reads as "the branch threw the
     * wrong type" rather than "the harness never started". Measured: the first
     * control run reported exactly that, and established nothing.
     */
    @BeforeAll
    public static void loadNative()
    {
        Security.addProvider(new JostleProvider());
        String bridge = Loader.getInterfaceTypeName();
        Assertions.assertTrue("JNI".equals(bridge) || "FFI".equals(bridge),
                "native interface did not resolve (got \"" + bridge + "\"); every cell below"
                        + " would fail with UnsatisfiedLinkError and mean nothing");

        // WHICH COPY RAN. BlockCipherSpi has a java9 override of the very method
        // under test, and the two are served from different places: a classes
        // DIRECTORY means the java8 baseline (the base :jostle:test leg, which
        // has no jar on its classpath), a JAR means the java9 copy via
        // Multi-Release. Recorded, never asserted - the point is that every
        // leg's XML says which copy it exercised, because a fix applied to one
        // copy is green on the other's legs.
        Object src = null;
        try
        {
            // BlockCipherSpi is package-private, so it is reached through the
            // public subclass whose superclass it is.
            Class<?> spi = AESBlockCipherSpi.class.getSuperclass();
            src = spi.getProtectionDomain().getCodeSource().getLocation();
        }
        catch (Throwable ignored)
        {
            // A null CodeSource is legal; the line below then says so.
        }
        System.out.println("[MT-65] bridge=" + bridge + "  BlockCipherSpi code source=" + src);
        System.out.flush();
    }

    /** 32 bytes: two AES blocks, so NoPadding needs no alignment fudging. */
    private static final int INPUT_LEN = 32;

    /**
     * Delegates every native call, but under-reports {@code getFinalSize} on the
     * first invocation only - see the class note on why a consistent lie would
     * measure nothing.
     */
    static final class ShortReportingNi implements BlockCipherNI
    {
        private final BlockCipherNI real;
        private int finalSizeCalls;

        ShortReportingNi(BlockCipherNI real)
        {
            this.real = real;
        }

        @Override
        public int getFinalSize(long ref, int length)
        {
            int truth = real.getFinalSize(ref, length);
            return finalSizeCalls++ == 0 ? truth - 1 : truth;
        }

        @Override
        public long ni_makeInstance(int cipher, int mode, int padding, int[] err)
        {
            return real.ni_makeInstance(cipher, mode, padding, err);
        }

        @Override
        public int ni_init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tagLen)
        {
            return real.ni_init(ref, oppmode, keyBytes, iv, tagLen);
        }

        @Override
        public int ni_getBlockSize(long ref)
        {
            return real.ni_getBlockSize(ref);
        }

        @Override
        public int ni_update(long ref, byte[] output, int outputOffset,
                             byte[] input, int inputOffset, int inputLen)
        {
            return real.ni_update(ref, output, outputOffset, input, inputOffset, inputLen);
        }

        @Override
        public int ni_doFinal(long ref, byte[] output, int outputOffset)
        {
            return real.ni_doFinal(ref, output, outputOffset);
        }

        @Override
        public int ni_updateAAD(long ref, byte[] input, int inputOffset, int inputLen)
        {
            return real.ni_updateAAD(ref, input, inputOffset, inputLen);
        }

        @Override
        public int ni_getFinalSize(long ref, int length)
        {
            return real.ni_getFinalSize(ref, length);
        }

        @Override
        public int ni_getUpdateSize(long ref, int length)
        {
            return real.ni_getUpdateSize(ref, length);
        }

        @Override
        public void ni_dispose(long ref)
        {
            real.ni_dispose(ref);
        }
    }

    /** Reaches the {@code protected} SPI methods by being one. */
    static final class Driver extends AESBlockCipherSpi
    {
        Driver(BlockCipherNI ni)
        {
            super(ni, OSSLCipher.AES128, OSSLMode.CBC);
        }

        byte[] drive(byte[] key, byte[] iv, byte[] input) throws Exception
        {
            engineSetPadding("NoPadding");
            engineInit(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv), new SecureRandom());
            return engineDoFinal(input, 0, input.length);
        }
    }

    private static byte[] rand(int n)
    {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    /**
     * An internal sizing miss surfaces as a {@code ProviderException} naming the
     * miss, with the {@code ShortBufferException} preserved as its cause.
     *
     * <p>Before the MT-65 fix this same test sees
     * {@code IllegalBlockSizeException("output buffer too small")} - the control
     * that proves it reaches the catch at all.
     */
    @Test
    public void internalSizingMissIsReportedAsAnInternalDefect() throws Exception
    {
        Driver d = new Driver(new ShortReportingNi(NISelector.BlockCipherNI));
        Throwable t = Assertions.assertThrows(Throwable.class,
                () -> d.drive(rand(16), rand(16), rand(INPUT_LEN)));

        // An Error here is the harness failing, not the provider answering.
        // Without this arm an UnsatisfiedLinkError becomes a type-mismatch
        // message that looks exactly like a real wrong-type result.
        if (t instanceof Error)
        {
            Assertions.fail("harness fault, not a measurement: " + t.getClass().getName()
                    + " (" + t.getMessage() + ")");
        }

        Assertions.assertEquals(ProviderException.class, t.getClass(),
                "an internal sizing miss must be a ProviderException, not "
                        + t.getClass().getName() + " (" + t.getMessage() + ")");
        Assertions.assertNotNull(t.getCause(), "the ShortBufferException must be preserved as the cause");
        Assertions.assertEquals(ShortBufferException.class, t.getCause().getClass(),
                "the cause must be the ShortBufferException that was caught");

        String m = t.getMessage();
        Assertions.assertNotNull(m, "the message must name the miss");
        Assertions.assertTrue(m.contains(String.valueOf(INPUT_LEN - 1)) && m.contains(String.valueOf(INPUT_LEN)),
                "the message must name the size reported (" + (INPUT_LEN - 1)
                        + ") and the size needed (" + INPUT_LEN + "); was: " + m);
        Assertions.assertFalse(m.toLowerCase().contains("block"),
                "the message must not say \"block\" - that reads as caller misalignment,"
                        + " which is the defect MT-65 exists to remove; was: " + m);
    }

    /**
     * The positive control: with the REAL NI and the same inputs the operation
     * succeeds and produces a full-length result.
     *
     * <p>Without this, a Driver that failed for some unrelated reason - a bad
     * key length, an unsupported mode - would satisfy the test above and look
     * like the branch firing.
     */
    @Test
    public void theSameDriverSucceedsWithTheUndecoratedNi() throws Exception
    {
        Driver d = new Driver(NISelector.BlockCipherNI);
        byte[] out = d.drive(rand(16), rand(16), rand(INPUT_LEN));
        Assertions.assertNotNull(out);
        Assertions.assertEquals(INPUT_LEN, out.length,
                "AES-128/CBC/NoPadding on " + INPUT_LEN + " bytes must return " + INPUT_LEN);
    }

    /**
     * Proves the fault construction is what the class note says: the decorator
     * lies ONCE.
     *
     * <p>A consistent liar would leave both sides of the capacity check agreeing
     * and raise nothing, so the whole witness rests on this property. It is
     * checked against a FIXED delegate rather than the live NI, so the assertion
     * is about the decorator's counter and nothing else.
     */
    @Test
    public void theDecoratorLiesOnlyOnItsFirstCall()
    {
        final int fixed = 100;
        ShortReportingNi ni = new ShortReportingNi(new FixedFinalSizeNi(fixed));

        Assertions.assertEquals(fixed - 1, ni.getFinalSize(0L, INPUT_LEN), "first call must under-report");
        Assertions.assertEquals(fixed, ni.getFinalSize(0L, INPUT_LEN), "second call must tell the truth");
        Assertions.assertEquals(fixed, ni.getFinalSize(0L, INPUT_LEN), "and every call after it");
    }

    /**
     * A delegate that answers only {@code getFinalSize}. Every other native call
     * throws, so if the decorator ever routed one here the test would say so
     * rather than silently succeeding.
     */
    static final class FixedFinalSizeNi implements BlockCipherNI
    {
        private final int size;

        FixedFinalSizeNi(int size)
        {
            this.size = size;
        }

        @Override
        public int getFinalSize(long ref, int length)
        {
            return size;
        }

        private static UnsupportedOperationException notUsed()
        {
            return new UnsupportedOperationException("this delegate answers getFinalSize only");
        }

        @Override
        public long ni_makeInstance(int cipher, int mode, int padding, int[] err)
        {
            throw notUsed();
        }

        @Override
        public int ni_init(long ref, int oppmode, byte[] keyBytes, byte[] iv, int tagLen)
        {
            throw notUsed();
        }

        @Override
        public int ni_getBlockSize(long ref)
        {
            throw notUsed();
        }

        @Override
        public int ni_update(long ref, byte[] output, int outputOffset,
                             byte[] input, int inputOffset, int inputLen)
        {
            throw notUsed();
        }

        @Override
        public int ni_doFinal(long ref, byte[] output, int outputOffset)
        {
            throw notUsed();
        }

        @Override
        public int ni_updateAAD(long ref, byte[] input, int inputOffset, int inputLen)
        {
            throw notUsed();
        }

        @Override
        public int ni_getFinalSize(long ref, int length)
        {
            throw notUsed();
        }

        @Override
        public int ni_getUpdateSize(long ref, int length)
        {
            throw notUsed();
        }

        @Override
        public void ni_dispose(long ref)
        {
            throw notUsed();
        }
    }
}
