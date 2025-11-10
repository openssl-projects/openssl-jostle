package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;

import javax.crypto.ShortBufferException;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;

/**
 * Test using FFI the internal layer that actually drives OpenSSL.
 * This layer is called by both JNI and FFI, while you can call these directly via FFI
 * we make no guarantees about stability.
 */
public class BlockCipherInternalLayerTest
{
    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
    }

    @Test
    public void testBlock_cipher_ctx_init__nullKey() throws Exception
    {

        // The bulk of block_cipher_ctx_init can be tested via the front door, JNI/FFI.
        // The test for a null key is caught in both FFI and JNI layers before hitting this function.

        // There is a NULL check for the key in this method we need to trigger.

        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_init").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return value
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_INT, // opp_mode
                        ValueLayout.ADDRESS, // key
                        ValueLayout.JAVA_LONG, // key_len
                        ValueLayout.ADDRESS, // iv
                        ValueLayout.JAVA_LONG // iv_len
                ), Linker.Option.critical(true));


        long ref = 0;
        try
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, 0, MemorySegment.NULL, 16L, MemorySegment.NULL, 0L);
            BlockCipherNI.handleInitErrorCodes(ErrorCode.forCode(code), 16, 0);

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(InvalidKeyException.class, e.getClass());
            Assertions.assertEquals("key is null", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }

    }


    @Test
    public void testBlock_cipher_ctx_update_nullInput() throws Exception
    {

        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_update").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return value
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // input
                        ValueLayout.JAVA_LONG, // in_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG // out_len
                ), Linker.Option.critical(true));


        long ref = 0;
        try
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, MemorySegment.NULL, 16L, MemorySegment.ofArray(new byte[16]), 16L);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass());
            Assertions.assertEquals("input is null", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }

    }


    @Test
    public void testBlock_cipher_ctx_update_nullOutput() throws Exception
    {

        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_update").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return value
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // input
                        ValueLayout.JAVA_LONG, // in_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG // out_len
                ), Linker.Option.critical(true));


        long ref = 0;
        try
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, MemorySegment.ofArray(new byte[16]), 16L, MemorySegment.NULL, 16L);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass());
            Assertions.assertEquals("output is null", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }

    }

    @Test
    public void testBlock_cipher_ctx_update__inputPastInt32PosMax() throws Exception
    {
        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_update").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return ptr
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // input
                        ValueLayout.JAVA_LONG, // in_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG // output len
                ), Linker.Option.critical(true));


        long ref = 0;
        try (Arena arena = Arena.ofConfined())
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            MemorySegment input = MemorySegment.ofArray(new byte[16]);
            MemorySegment output = MemorySegment.ofArray(new byte[16]);

            //
            // Test May cause SEGFAULT if not correctly handled.
            //
            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, input, 1L + Integer.MAX_VALUE, output, output.byteSize());
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass());
            Assertions.assertEquals("input too long int32", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }

    }

    @Test
    public void testBlock_cipher_ctx_update__outputPastInt32PosMax() throws Exception
    {
        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_update").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return ptr
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // input
                        ValueLayout.JAVA_LONG, // in_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG // output len
                ), Linker.Option.critical(true));


        long ref = 0;
        try (Arena arena = Arena.ofConfined())
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            MemorySegment input = MemorySegment.ofArray(new byte[16]);
            MemorySegment output = MemorySegment.ofArray(new byte[16]);

            // May cause SEGFAULT if check not correctly implemented.

            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, input, input.byteSize(), output, 1L + Integer.MAX_VALUE);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass());
            Assertions.assertEquals("output too long int32", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }

    @Test
    public void testBlockCipherFinal_outputPastInt32PosMax() throws Exception
    {
        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_final").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return ptr
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // Output
                        ValueLayout.JAVA_LONG // out_len
                ), Linker.Option.critical(true));


        long ref = 0;
        try (Arena arena = Arena.ofConfined())
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            MemorySegment output = MemorySegment.ofArray(new byte[16]);


            // May cause SEGFAULT if check not correctly handled.
            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, output, 1L + Integer.MAX_VALUE);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(IllegalArgumentException.class, e.getClass());
            Assertions.assertEquals("output too long int32", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }
    }


    @Test
    public void testBlock_cipher_ctx_update_outLenShort() throws Exception
    {

        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_update").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return value
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // input
                        ValueLayout.JAVA_LONG, // in_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG // out_len
                ), Linker.Option.critical(true));


        long ref = 0;
        try
        {
            ref = TestNISelector.getBlockCipher().makeInstance(14, 0, 1);

            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, MemorySegment.ofArray(new byte[16]), 16L, MemorySegment.ofArray(new byte[16]), 15L);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(ShortBufferException.class, e.getClass());
            Assertions.assertEquals("output too small", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }

    }

    @Test
    public void testBlock_cipher_ctx_update_invalidOppMode() throws Exception
    {

        //
        // With this test we use FFI to manipulate a struct so that we can induce an
        // error where we had initialized it with an invalid operation mode (ENCRYPT, DECRYPT, etc)
        // And check the result.
        //

        Assumptions.assumeTrue(Loader.isFFI());

        final SymbolLookup lookup = SymbolLookup.loaderLookup();
        final Linker linker = Linker.nativeLinker();

        var rawBlockCipherUpdate = lookup.find("block_cipher_ctx_update").orElseThrow();
        var rawBlockCipherUpdateHandler = linker.downcallHandle(rawBlockCipherUpdate,
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT, // Return value
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, // input
                        ValueLayout.JAVA_LONG, // in_len
                        ValueLayout.ADDRESS, // output
                        ValueLayout.JAVA_LONG // out_len
                ), Linker.Option.critical(true));


        long ref = 0;
        try
        {
            ref = TestNISelector.getBlockCipher().makeInstance(8, 0, 1);

            MemorySegment key = MemorySegment.ofArray(new byte[16]);

            // Init
            Assertions.assertEquals(0, (int) linker.downcallHandle(lookup.find("block_cipher_ctx_init").orElseThrow(),
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,

                            ValueLayout.JAVA_LONG, // ctx
                            ValueLayout.JAVA_INT, // opp_mode
                            ValueLayout.ADDRESS, // key
                            ValueLayout.JAVA_LONG, //key_len
                            ValueLayout.ADDRESS, // iv
                            ValueLayout.JAVA_LONG, // iv_len
                            ValueLayout.JAVA_INT // tag_len
                            ),
                    Linker.Option.critical(true)).invokeExact(ref, 1, key, key.byteSize(), MemorySegment.NULL, 0L, 0));

            //
            // This test is making assumptions about struct layout that may prove to be incorrect
            //
            MemorySegment input = MemorySegment.ofAddress(ref).reinterpret(8 + 4 + 4 + 4 + 4 + 8);

            if (ByteOrder.nativeOrder().equals(ByteOrder.LITTLE_ENDIAN))
            {
                Assertions.assertEquals(1, input.get(ValueLayout.JAVA_BYTE, 8L + 4 + 4 + 4), "expected initial opp mode of 1 LE");
                input.set(ValueLayout.JAVA_BYTE, 8L + 4 + 4 + 4, (byte) 10);
            } else
            {
                Assertions.assertEquals(1, input.get(ValueLayout.JAVA_BYTE, 8L + 4 + 4 + 4 + 3), "expected initial opp mode of 1 BE");
                input.set(ValueLayout.JAVA_BYTE, 8L + 4 + 4 + 4 + 3, (byte) 10);
            }

            int code = (int) rawBlockCipherUpdateHandler.invokeExact(ref, MemorySegment.ofArray(new byte[16]), 16L, MemorySegment.ofArray(new byte[16]), 16L);
            BlockCipherNI.handleUpdateErrorCodes(ErrorCode.forCode(code));

            Assertions.fail();
        } catch (Throwable e)
        {
            Assertions.assertSame(IllegalStateException.class, e.getClass());
            Assertions.assertEquals("invalid operation mode", e.getMessage());
        } finally
        {
            TestNISelector.getBlockCipher().dispose(ref);
        }

    }

}
