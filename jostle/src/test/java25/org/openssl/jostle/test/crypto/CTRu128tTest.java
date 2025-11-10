package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.Loader;
import org.openssl.jostle.util.Arrays;

import java.lang.foreign.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Use FFI to test counter.
 */
public class CTRu128tTest
{

    final static SymbolLookup lookup;
    final static Linker linker;
    final static Map<String, Long> offsets = new HashMap<>();

    static
    {
        CryptoServicesRegistrar.isNativeAvailable(); // Trigger Loading
        lookup = SymbolLookup.loaderLookup();
        linker = Linker.nativeLinker();

        offsets.put("HIGH", 0L);
        offsets.put("LOW", 8L);
        offsets.put("iv_len", 16L);
        offsets.put("original_ctr", 24L);
        offsets.put("limit", 40L);
        offsets.put("rolled", 48L);
    }


    private MemorySegment newInstance() throws Throwable
    {
        MemorySegment ms = (MemorySegment) linker.downcallHandle(
                        lookup.find("ctr_u128_new").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS))
                .invokeExact();

        ms = ms.reinterpret(56);
        return ms;
    }

    private void dispose(MemorySegment ms) throws Throwable
    {
        linker.downcallHandle(lookup.find("counter_free").orElseThrow(), FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))
                .invokeExact(ms);
    }


    private void init(MemorySegment ctr, byte[] iv) throws Throwable
    {

        MemorySegment ivSegment = MemorySegment.ofArray(iv);

        linker.downcallHandle(
                lookup.find("counter_init").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS, // ctr ref
                        ValueLayout.ADDRESS, // iv
                        ValueLayout.JAVA_LONG // iv_len
                )
                , Linker.Option.critical(true)
        ).invokeExact(ctr, ivSegment, ivSegment.byteSize());

    }

    private void sub(MemorySegment ctr, long high, long low) throws Throwable
    {
        linker.downcallHandle(
                lookup.find("counter_sub").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS, // ctr ref
                        ValueLayout.JAVA_LONG, // high
                        ValueLayout.JAVA_LONG // low
                )
                , Linker.Option.critical(true)
        ).invokeExact(ctr, high, low);
    }

    private void add(MemorySegment ctr, long high, long low) throws Throwable
    {
        linker.downcallHandle(
                lookup.find("counter_add").orElseThrow(),
                FunctionDescriptor.ofVoid(
                        ValueLayout.ADDRESS, // ctr ref
                        ValueLayout.JAVA_LONG, // high
                        ValueLayout.JAVA_LONG // low
                )
                , Linker.Option.critical(true)
        ).invokeExact(ctr, high, low);
    }


    @Test
    public void testInitWithIV() throws Throwable
    {
        Assumptions.assumeTrue(Loader.isFFI());
        var ctr = newInstance();

        try
        {
            for (int t = 9; t <= 15; t++)
            {
                byte[] iv = new byte[t];
                Arrays.fill(iv, (byte) t);
                byte[] expCtr = new byte[16];
                System.arraycopy(iv, 0, expCtr, 0, iv.length);

                init(ctr, iv);
                long limit = ctr.get(ValueLayout.JAVA_LONG_UNALIGNED, offsets.get("limit"));
                long expectedLimit = 1L << ((16 - t) * 8);

                Assertions.assertEquals(expectedLimit, limit);

                var origCtr = ctr.asSlice(offsets.get("original_ctr"), 16).toArray(ValueLayout.JAVA_BYTE);

                Assertions.assertArrayEquals(expCtr, origCtr);

            }
        } finally
        {
            dispose(ctr);
        }

    }

    private int valid(MemorySegment ms) throws Throwable
    {
        return (int) linker.downcallHandle(
                        lookup.find("counter_valid").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
                .invokeExact(ms);
    }


    @Test
    public void testUnderflow() throws Throwable
    {
        Assumptions.assumeTrue(Loader.isFFI());
        var ctr = newInstance();
        try
        {
            init(ctr, new byte[16]);
            sub(ctr, 0L, 1L);
            int rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(-1, rolled);
        } finally
        {
            dispose(ctr);
        }
    }

    @Test
    public void testOverflow_16() throws Throwable
    {
        Assumptions.assumeTrue(Loader.isFFI());
        var ctr = newInstance();
        try
        {
            init(ctr, new byte[16]);

            add(ctr, 0xFFFFFFFFFFFFFFFFL, 0xFFFFFFFFFFFFFFFFL);
            int rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(0, rolled);

            Assertions.assertEquals(1, valid(ctr));


            add(ctr, 0, 1L);
            rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(1, rolled);

            Assertions.assertEquals(0, valid(ctr));

        } finally
        {
            dispose(ctr);
        }
    }


    @Test
    public void testOverflow_8() throws Throwable
    {
        Assumptions.assumeTrue(Loader.isFFI());
        var ctr = newInstance();
        try
        {
            init(ctr, new byte[8]);

            add(ctr, 0, 0xFFFFFFFFFFFFFFFFL);
            int rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(0, rolled);

            Assertions.assertEquals(1, valid(ctr));


            add(ctr, 0, 1L);

            //
            // Rolling only refers to 128b over / under flow.
            // So this should still be zero
            //
            rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(0, rolled);

            // Counter should not be valid.
            Assertions.assertEquals(0, valid(ctr));

        } finally
        {
            dispose(ctr);
        }
    }


    @Test
    public void testOverflow_8_high_non_zero() throws Throwable
    {
        Assumptions.assumeTrue(Loader.isFFI());
        var ctr = newInstance();
        try
        {
            init(ctr, new byte[8]);

            add(ctr, 0, 0xFFFFFFFFFFFFFFFFL);
            int rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(0, rolled);

            Assertions.assertEquals(1, valid(ctr));


            // So the high u64 should always be zero for iv_len != 16
            // So by incrementing it we leave the low u64 valid and make the high u64 non-zero and
            // invalid
            add(ctr, 1, 0);

            Assertions.assertEquals(0, valid(ctr));


            //
            // Rolling only refers to 128b over / under flow.
            // So this should still be zero
            //
            rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
            Assertions.assertEquals(0, rolled);

        } finally
        {
            dispose(ctr);
        }
    }


    @Test
    public void testOverflow_9_15() throws Throwable
    {
        Assumptions.assumeTrue(Loader.isFFI());
        var ctr = newInstance();
        try
        {
            long addend = 0xFFFFFFFFFFFFFFFFL;
            for (int t = 9; t <= 15; t++)
            {
                addend >>>= 8;

                init(ctr, new byte[t]);

                add(ctr, 0, addend);
                int rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
                Assertions.assertEquals(0, rolled); // not rolled

                Assertions.assertEquals(1, valid(ctr)); // Valid at this point.

                add(ctr, 0, 1L); // Exceed limit for the iv_len
                Assertions.assertEquals(0, valid(ctr)); // Should be invalid

                rolled = ctr.get(ValueLayout.JAVA_INT_UNALIGNED, offsets.get("rolled"));
                Assertions.assertEquals(0, rolled); // Not rolled
            }
        } finally
        {
            dispose(ctr);
        }
    }

}
