package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class MacLimitTest
{

    private static final SecureRandom RANDOM = new SecureRandom();

    private final MacServiceNI macNI = TestNISelector.getMacServiceNI();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }


    @Test
    public void makeInstance_macNameNull()
    {
        try
        {
            macNI.allocateMac(null, "cats");
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("name is null", e.getMessage());
        }
    }

    @Test
    public void makeInstance_functionNameNull()
    {
        try
        {
            macNI.allocateMac("HMAC", null);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("mac function name is null", e.getMessage());
        }
    }

    @Test
    public void poly1305_keyLengthBoundary() throws Exception
    {
        // Poly1305 (RFC 8439) requires exactly a 32-byte one-time key. 31 and 33
        // are rejected with "invalid key length for mac type" (JO_UNKNOWN_KEY_LEN
        // from the POLY1305 branch of init_mac_ctx); 32 is accepted.
        for (int kl : new int[]{31, 33})
        {
            long ref = macNI.allocateMac("POLY1305", "POLY1305");
            try
            {
                macNI.engineInit(ref, new byte[kl]);
                Assertions.fail("expected rejection for key len " + kl);
            }
            catch (InvalidKeyException e)
            {
                Assertions.assertEquals("invalid key length for mac type", e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }

        long ref = macNI.allocateMac("POLY1305", "POLY1305");
        try
        {
            macNI.engineInit(ref, new byte[32]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void init_keyNull()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, null);
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("key is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void update_inputNull() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, null, 0, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("input is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputOffsetNegative() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], -1, 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputLenNegative() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 0, -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void update_inputOutOfRange_1() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 1, 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void update_inputOutOfRange_2() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[1], 0, 2);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_notInitialised_array() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            //macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, new byte[32], 0, 32);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_notInitialised_byte() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            //macNI.engineInit(ref, new byte[16]);
            macNI.engineUpdate(ref, (byte) 1);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void doFinal_outputNull() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, null, 0);
            Assertions.fail();
        }
        catch (NullPointerException e)
        {
            Assertions.assertEquals("output is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputOffsetNegative() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], -1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputTooSmall() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], 1);
            Assertions.fail();
        }
        catch (IllegalArgumentException e)
        {
            Assertions.assertEquals("output offset + mac len is out of range", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void doFinal_notInitialised() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-512");
        Assertions.assertTrue(ref > 0);
        try
        {
            //macNI.engineInit(ref, new byte[16]);
            macNI.doFinal(ref, new byte[32], 1);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void getMacLength_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.getMacLength(ref);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    // macLengthMeta is the keyless counterpart to getMacLength: it reads the
    // length from OpenSSL algorithm metadata (digest output size / cipher
    // block size) and so MUST answer before init, where getMacLength above
    // returns JO_NOT_INITIALIZED. These are the positive contract tests.
    @Test
    public void macLengthMeta_hmac_beforeInit_returnsDigestSize()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            // No engineInit: keyless query must still succeed.
            Assertions.assertEquals(32, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_cmac_beforeInit_returnsBlockSize()
    {
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            // CMAC length == AES block size (16), independent of key length,
            // so it is answerable before a key is supplied.
            Assertions.assertEquals(16, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void macLengthMeta_hmac_unknownDigest_opensslError()
    {
        long ref = macNI.allocateMac("HMAC", "NOT-A-REAL-DIGEST");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.macLengthMeta(ref);
            Assertions.fail();
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:") && e.getMessage().contains("NOT-A-REAL-DIGEST"), e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void reset_notInitialised()
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.reset(ref);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void reset_nullRef()
    {
        // Both backends silently return JO_SUCCESS for the spurious-reset case;
        // no exception expected.
        macNI.reset(0L);
    }


    @Test
    public void makeInstance_unknownAlgorithm()
    {
        try
        {
            macNI.allocateMac("ZZZZZZZ", "SHA-256");
            Assertions.fail();
        }
        catch (OpenSSLException ignored)
        {
            // EVP_MAC_fetch fails -> JO_OPENSSL_ERROR -> OpenSSLException.
            // Message text is OpenSSL-version-dependent so we don't assert on it.
        }
    }


    @Test
    public void cmac_unknownCipher() throws Exception
    {
        long ref = macNI.allocateMac("CMAC", "des-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            Assertions.fail();
        }
        catch (IllegalStateException e)
        {
            Assertions.assertEquals("unexpected state", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void cmac_invalidKeyLen()
    {
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[17]);
            Assertions.fail();
        }
        catch (InvalidKeyException e)
        {
            Assertions.assertEquals("invalid key length for mac type", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void init_reInitDifferentKey() throws Exception
    {
        // Exercises mac_init's alias-safe re-init: free-old then alloc-new used to be
        // the order, which would corrupt the key if the caller happened to alias mctx->key.
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[16]);
            macNI.engineInit(ref, new byte[32]);
            macNI.engineInit(ref, new byte[64]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void init_emptyKey() throws Exception
    {
        // Native layer can accept zero len keys, SecretKeySpec will not,
        // however.
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[0]);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    // ---------------------------------------------------------------------
    // Null (0) mac_ctx handle: every dereferencing entry point must return a
    // typed JO_MAC_CTX_IS_NULL rejection (IllegalArgumentException "mac
    // context is null"), NOT a jo_assert that aborts the JVM. dispose/reset
    // deliberately no-op on a null handle (see reset_nullRef) and are exempt.
    // Runs on both JNI and FFI via integrationTest25{JNI,FFI} — both bridges
    // must return the same code.
    // ---------------------------------------------------------------------

    @Test
    public void init_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineInit(0L, new byte[16]));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void updateByte_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineUpdate(0L, (byte) 1));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void updateBytes_nullCtx_rejectedTyped()
    {
        // ctx is checked before the input/range checks, so a non-null input
        // with a null handle still surfaces the handle rejection.
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineUpdate(0L, new byte[4], 0, 4));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void doFinal_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.doFinal(0L, new byte[32], 0));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void getMacLength_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.getMacLength(0L));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void macLengthMeta_nullCtx_rejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.macLengthMeta(0L));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }


    // ---------------------------------------------------------------------
    // Integer.MIN_VALUE probes on every int offset/length (testing.md: a
    // check written `len > 0` accepts MIN_VALUE; Math.abs(MIN_VALUE) is still
    // negative). The -1 side is covered by the update_/doFinal_ tests above.
    // ---------------------------------------------------------------------

    @Test
    public void update_inputOffset_minValue() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(ref, new byte[16]);
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> macNI.engineUpdate(ref, new byte[1], Integer.MIN_VALUE, 1));
            Assertions.assertEquals("input offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void update_inputLen_minValue() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(ref, new byte[16]);
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> macNI.engineUpdate(ref, new byte[1], 0, Integer.MIN_VALUE));
            Assertions.assertEquals("input len is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void doFinal_outputOffset_minValue() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(ref, new byte[16]);
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> macNI.doFinal(ref, new byte[32], Integer.MIN_VALUE));
            Assertions.assertEquals("output offset is negative", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    // ---------------------------------------------------------------------
    // Offset-write contract for doFinal, verified functionally against a
    // reference MAC (testing.md). MAC is deterministic, so the written region
    // must equal the reference byte-for-byte; a window one byte earlier must
    // not, proving the write landed at exactly the requested offset.
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        byte[] key = new byte[32];
        byte[] input = new byte[64 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(input);

        byte[] reference = new byte[32];
        long refA = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(refA, key);
            macNI.engineUpdate(refA, input, 0, input.length);
            Assertions.assertEquals(32, macNI.doFinal(refA, reference, 0));
        }
        finally
        {
            macNI.dispose(refA);
        }

        int prefix = 7;
        byte[] big = new byte[prefix + 32];
        RANDOM.nextBytes(big);
        byte[] savedPrefix = Arrays.copyOf(big, prefix);

        long refB = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(refB, key);
            macNI.engineUpdate(refB, input, 0, input.length);
            Assertions.assertEquals(32, macNI.doFinal(refB, big, prefix));
        }
        finally
        {
            macNI.dispose(refB);
        }

        Assertions.assertArrayEquals(savedPrefix, Arrays.copyOf(big, prefix),
                "prefix region was clobbered");
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(big, prefix, prefix + 32),
                "output region is not the expected MAC");
        Assertions.assertFalse(
                Arrays.equals(reference, Arrays.copyOfRange(big, prefix - 1, prefix - 1 + 32)),
                "MAC appears one byte before the requested offset");
    }


    // ---------------------------------------------------------------------
    // Aliased-buffer operation (testing.md): a caller reuses the update-input
    // array as the doFinal-output array. The tag must be correct and every
    // byte of the destination outside the tag region must be untouched.
    // ---------------------------------------------------------------------

    @Test
    public void doFinal_aliased_tagAfterMessage() throws Exception
    {
        assertAliasedMacCorrect(40, 40);
    }

    @Test
    public void doFinal_aliased_tagOverwritesMessageStart() throws Exception
    {
        assertAliasedMacCorrect(40, 0);
    }

    @Test
    public void doFinal_aliased_tagMidMessage() throws Exception
    {
        assertAliasedMacCorrect(64, 16);
    }

    private void assertAliasedMacCorrect(int msgLen, int tagOff) throws Exception
    {
        byte[] key = new byte[32];
        byte[] msg = new byte[msgLen];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(msg);

        byte[] reference = new byte[32];
        long refA = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(refA, key);
            macNI.engineUpdate(refA, msg, 0, msg.length);
            Assertions.assertEquals(32, macNI.doFinal(refA, reference, 0));
        }
        finally
        {
            macNI.dispose(refA);
        }

        int cap = Math.max(msgLen, tagOff + 32) + 8;
        byte[] buf = new byte[cap];
        RANDOM.nextBytes(buf);
        System.arraycopy(msg, 0, buf, 0, msgLen);
        byte[] snapshot = buf.clone();

        int written;
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        try
        {
            macNI.engineInit(ref, key);
            macNI.engineUpdate(ref, buf, 0, msgLen);
            written = macNI.doFinal(ref, buf, tagOff);
        }
        finally
        {
            macNI.dispose(ref);
        }

        String where = "msgLen=" + msgLen + " tagOff=" + tagOff;
        Assertions.assertEquals(32, written, where + " tag length");
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(buf, tagOff, tagOff + written),
                where + ": aliased MAC differs from the reference");
        Assertions.assertArrayEquals(Arrays.copyOf(snapshot, tagOff), Arrays.copyOf(buf, tagOff),
                where + ": bytes before the tag offset were clobbered");
        Assertions.assertArrayEquals(
                Arrays.copyOfRange(snapshot, tagOff + written, cap),
                Arrays.copyOfRange(buf, tagOff + written, cap),
                where + ": bytes after the tag were clobbered");
    }


}
