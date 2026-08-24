package org.openssl.jostle.test.mac;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.InvalidAlgorithmParameterException;
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
                macNI.engineInit(ref, new byte[kl], null, null, 0);
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
            macNI.engineInit(ref, new byte[32], null, null, 0);
        }
        finally
        {
            macNI.dispose(ref);
        }
    }


    @Test
    public void init_keyNull() throws Exception
    {
        long ref = macNI.allocateMac("HMAC", "SHA-256");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, null, null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            //macNI.engineInit(ref, new byte[16], null, null, 0);
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
            //macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            //macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
    public void cmac_invalidKeyLen() throws Exception
    {
        long ref = macNI.allocateMac("CMAC", "aes-cbc");
        Assertions.assertTrue(ref > 0);
        try
        {
            macNI.engineInit(ref, new byte[17], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
            macNI.engineInit(ref, new byte[32], null, null, 0);
            macNI.engineInit(ref, new byte[64], null, null, 0);
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
            macNI.engineInit(ref, new byte[0], null, null, 0);
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
                () -> macNI.engineInit(0L, new byte[16], null, null, 0));
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(ref, new byte[16], null, null, 0);
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
            macNI.engineInit(refA, key, null, null, 0);
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
            macNI.engineInit(refB, key, null, null, 0);
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


    // ---------------------------------------------------------------------
    // GMAC: the IV parameter ni_init gained for it (WI-2). Mirrors
    // FIPSMacLimitTest's GMAC block - the two bridges must reject identical
    // inputs with identical codes, and only running both proves it.
    // ---------------------------------------------------------------------

    @Test
    public void gmac_initWithoutIv_rejectedTyped()
    {
        long ref = macNI.allocateMac("GMAC", "aes-gcm");
        Assertions.assertTrue(ref > 0);
        try
        {
            InvalidAlgorithmParameterException e =
                    Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                            () -> macNI.engineInit(ref, new byte[16], null, null, 0));
            Assertions.assertEquals("iv is null", e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void gmac_initWithZeroLengthIv_refusedByOpenSSL()
    {
        // Not pre-checked: GMAC inherits GCM's variable-length nonce and only
        // 0 is illegal, so OpenSSL owns the legality ("invalid iv length").
        long ref = macNI.allocateMac("GMAC", "aes-gcm");
        Assertions.assertTrue(ref > 0);
        try
        {
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> macNI.engineInit(ref, new byte[16], new byte[0], null, 0));
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void gmac_everyAcceptedIvLengthInitsAndProducesA16ByteTag() throws Exception
    {
        for (int ivLen : new int[]{1, 8, 11, 12, 13, 16, 32})
        {
            long ref = macNI.allocateMac("GMAC", "aes-gcm");
            Assertions.assertTrue(ref > 0);
            try
            {
                byte[] iv = new byte[ivLen];
                RANDOM.nextBytes(iv);
                macNI.engineInit(ref, new byte[16], iv, null, 0);
                macNI.engineUpdate(ref, new byte[64], 0, 64);
                Assertions.assertEquals(16, macNI.doFinal(ref, new byte[16], 0), "ivLen=" + ivLen);
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void nonGmacMacs_initWithIv_rejectedTyped()
    {
        // Fail loud rather than ignore: a silently-dropped IV yields a tag the
        // caller believes was nonce-bound and is not. POLY1305 is here too, as
        // the base provider serves it where JSLFIPS does not.
        String[][] macs = {{"HMAC", "SHA-256"}, {"CMAC", "aes-cbc"}, {"POLY1305", "POLY1305"}};
        for (String[] m : macs)
        {
            long ref = macNI.allocateMac(m[0], m[1]);
            Assertions.assertTrue(ref > 0);
            try
            {
                InvalidAlgorithmParameterException e =
                        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                                () -> macNI.engineInit(ref, new byte[32], new byte[12], null, 0),
                                m[0] + " accepted an IV");
                Assertions.assertEquals("mac takes no iv", e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void gmac_invalidKeyLen()
    {
        for (int keyLen : new int[]{0, 1, 15, 17, 23, 25, 31, 33, 64})
        {
            long ref = macNI.allocateMac("GMAC", "aes-gcm");
            Assertions.assertTrue(ref > 0);
            try
            {
                InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                        () -> macNI.engineInit(ref, new byte[keyLen], new byte[12], null, 0),
                        "keyLen=" + keyLen);
                Assertions.assertEquals("invalid key length for mac type", e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void gmac_nullMacCtx_initRejectedTyped()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> macNI.engineInit(0L, new byte[16], new byte[12], null, 0));
        Assertions.assertEquals("mac context is null", e.getMessage());
    }

    @Test
    public void gmac_macLengthMeta_beforeInit_returnsBlockSize()
    {
        long ref = macNI.allocateMac("GMAC", "aes-gcm");
        Assertions.assertTrue(ref > 0);
        try
        {
            Assertions.assertEquals(16, macNI.macLengthMeta(ref));
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void gmac_doFinal_aliased_tagAfterMessage() throws Exception
    {
        assertAliasedMacCorrect("GMAC", "aes-gcm", 16, gmacIv(), 40, 40);
    }

    @Test
    public void gmac_doFinal_aliased_tagOverwritesMessageStart() throws Exception
    {
        assertAliasedMacCorrect("GMAC", "aes-gcm", 16, gmacIv(), 40, 0);
    }

    @Test
    public void gmac_doFinal_aliased_tagMidMessage() throws Exception
    {
        assertAliasedMacCorrect("GMAC", "aes-gcm", 16, gmacIv(), 64, 16);
    }

    private static byte[] gmacIv()
    {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        return iv;
    }

    private void assertAliasedMacCorrect(int msgLen, int tagOff) throws Exception
    {
        assertAliasedMacCorrect("HMAC", "SHA-256", 32, null, msgLen, tagOff);
    }

    // ---------------------------------------------------------------------
    // KMAC (SP 800-185) at the NI surface. KMAC is the only variable-length
    // MAC registered, so it is the only one whose init carries a customisation
    // string and an output length - and the only one where a wrong answer can
    // be a plausible tag of the wrong shape rather than an obvious failure.
    //
    // The key and output-length FLOORS are deliberately not pinned as absolute
    // numbers beyond mainline's: both move with the module's fipsinstall config
    // (4 -> 14 bytes of key under kmac-key-check, 1 -> 4 bytes of output under
    // no-short-mac), so the config-dependent boundary is a FIPS contract test.
    // Measured across four environments: fips-c-review/probes/kmac_probe.c.
    // ---------------------------------------------------------------------

    @Test
    public void kmac_customOnNonKmacMac_rejectedTyped() throws Exception
    {
        // Reachable only from the NI: MacServiceSPI refuses a KMACParameterSpec
        // for every MAC but KMAC. Rejected rather than ignored, because a
        // silently dropped S yields a tag that is wrong-but-self-consistent.
        for (String[] mac : new String[][]{{"HMAC", "SHA-256"}, {"CMAC", "aes-cbc"},
                {"GMAC", "aes-gcm"}, {"POLY1305", "POLY1305"}})
        {
            long ref = macNI.allocateMac(mac[0], mac[1]);
            try
            {
                macNI.engineInit(ref, new byte[32], mac[0].equals("GMAC") ? gmacIv() : null,
                        new byte[]{1, 2, 3}, 0);
                Assertions.fail(mac[0] + " accepted a customisation string");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                Assertions.assertEquals("mac takes no customisation string", e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void kmac_outputLengthOnNonKmacMac_rejectedTyped() throws Exception
    {
        for (String[] mac : new String[][]{{"HMAC", "SHA-256"}, {"CMAC", "aes-cbc"},
                {"GMAC", "aes-gcm"}, {"POLY1305", "POLY1305"}})
        {
            long ref = macNI.allocateMac(mac[0], mac[1]);
            try
            {
                macNI.engineInit(ref, new byte[32], mac[0].equals("GMAC") ? gmacIv() : null,
                        null, 16);
                Assertions.fail(mac[0] + " accepted an output length");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                Assertions.assertEquals("mac takes no output length", e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void kmac_negativeOutputLength_rejectedTyped() throws Exception
    {
        // A negative int would become a huge size_t past the cast and drive an
        // enormous allocation inside the provider, so it is rejected at the
        // bridge before any cast. MIN_VALUE is included because it survives
        // negation and Math.abs.
        for (int bad : new int[]{-1, Integer.MIN_VALUE})
        {
            long ref = macNI.allocateMac("KMAC-128", "KMAC-128");
            try
            {
                macNI.engineInit(ref, new byte[32], null, null, bad);
                Assertions.fail("accepted outLen=" + bad);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                Assertions.assertEquals("output length is negative", e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void kmac_macLengthMeta_beforeInit_returnsAlgorithmDefault()
    {
        // The keyless metadata query behind engineGetMacLength on a fresh SPI.
        for (String[] kmac : new String[][]{{"KMAC-128", "32"}, {"KMAC-256", "64"}})
        {
            long ref = macNI.allocateMac(kmac[0], kmac[0]);
            try
            {
                Assertions.assertEquals(Integer.parseInt(kmac[1]), macNI.macLengthMeta(ref),
                        kmac[0] + " default output length");
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void kmac_macLengthMetaStaysTheAlgorithmDefaultAfterASizedInit() throws Exception
    {
        // Property guard on mac_len_for's use of a FRESH EVP_MAC_CTX for KMAC.
        //
        // EVP_MAC_CTX_get_mac_size FOLLOWS a caller-requested size once the ctx
        // has been inited, so asking THIS ctx would return 48 here. The Java
        // side memoizes macLengthMeta per ALGORITHM NAME, so that answer would
        // poison the shared cache with one instance's chosen length and every
        // later KMAC128 would report 48 as its default.
        //
        // Falsifiable: point mac_len_for's KMAC arm at mctx->ctx instead of a
        // fresh one and this fails while the sibling default-length test above
        // stays green.
        long ref = macNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            Assertions.assertEquals(32, macNI.macLengthMeta(ref), "before init");
            macNI.engineInit(ref, new byte[32], null, null, 48);
            Assertions.assertEquals(48, macNI.getMacLength(ref),
                    "getMacLength must report THIS instance's requested length");
            Assertions.assertEquals(32, macNI.macLengthMeta(ref),
                    "macLengthMeta must stay the ALGORITHM default, not this instance's request");
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void kmac_zeroOutputLengthMeansDefaultNotAZeroLengthMac() throws Exception
    {
        // 0 is the "caller did not ask" sentinel and must never reach OpenSSL as
        // a real request: most builds accept size=0 and then emit a zero-length
        // MAC, which compares equal to every other zero-length tag. Passing 0
        // here must give the algorithm's default instead.
        long ref = macNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            macNI.engineInit(ref, new byte[32], null, null, 0);
            Assertions.assertEquals(32, macNI.getMacLength(ref));
            byte[] out = new byte[32];
            macNI.engineUpdate(ref, new byte[]{1, 2, 3}, 0, 3);
            Assertions.assertEquals(32, macNI.doFinal(ref, out, 0),
                    "outLen=0 must produce the default-length tag, never a zero-length one");
        }
        finally
        {
            macNI.dispose(ref);
        }
    }

    @Test
    public void kmac_customisationStringLengthBoundary() throws Exception
    {
        // OpenSSL owns this bound (512 bytes on every measured build) and
        // reports "invalid custom length"; we do not pre-check it, per the
        // classify-don't-pre-check rule. boundary and boundary+1.
        long ok = macNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            macNI.engineInit(ok, new byte[32], null, new byte[512], 0);
        }
        finally
        {
            macNI.dispose(ok);
        }

        long bad = macNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            macNI.engineInit(bad, new byte[32], null, new byte[513], 0);
            Assertions.fail("513-byte customisation string was accepted");
        }
        catch (OpenSSLException e)
        {
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
        }
        finally
        {
            macNI.dispose(bad);
        }
    }

    @Test
    public void kmac_keyLengthBoundary_mainlineFloor() throws Exception
    {
        // Mainline libcrypto - which is what the BASE provider always links
        // against - accepts keys from 4 bytes and up to 512, and refuses 3 and
        // 513 with "invalid key length". Both mainline 3.5.7 and 3.6.2 agree.
        // The FIPS module's -pedantic floor of 14 is a different contract and
        // is pinned in the FIPS tests, not here.
        for (int good : new int[]{4, 14, 512})
        {
            long ref = macNI.allocateMac("KMAC-128", "KMAC-128");
            try
            {
                macNI.engineInit(ref, new byte[good], null, null, 0);
            }
            finally
            {
                macNI.dispose(ref);
            }
        }

        for (int bad : new int[]{0, 3, 513})
        {
            long ref = macNI.allocateMac("KMAC-128", "KMAC-128");
            try
            {
                macNI.engineInit(ref, new byte[bad], null, null, 0);
                Assertions.fail("key length " + bad + " was accepted");
            }
            catch (OpenSSLException e)
            {
                Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
            }
            finally
            {
                macNI.dispose(ref);
            }
        }
    }

    @Test
    public void kmac_doFinal_writesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        byte[] key = new byte[32];
        byte[] input = new byte[64 + RANDOM.nextInt(256)];
        byte[] custom = new byte[]{'a', 'l', 'p', 'h', 'a'};
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(input);
        int outLen = 40;

        byte[] reference = new byte[outLen];
        long refA = macNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            macNI.engineInit(refA, key, null, custom, outLen);
            macNI.engineUpdate(refA, input, 0, input.length);
            Assertions.assertEquals(outLen, macNI.doFinal(refA, reference, 0));
        }
        finally
        {
            macNI.dispose(refA);
        }

        int prefix = 7;
        byte[] big = new byte[prefix + outLen];
        RANDOM.nextBytes(big);
        byte[] savedPrefix = Arrays.copyOf(big, prefix);

        long refB = macNI.allocateMac("KMAC-128", "KMAC-128");
        try
        {
            macNI.engineInit(refB, key, null, custom, outLen);
            macNI.engineUpdate(refB, input, 0, input.length);
            Assertions.assertEquals(outLen, macNI.doFinal(refB, big, prefix));
        }
        finally
        {
            macNI.dispose(refB);
        }

        Assertions.assertArrayEquals(savedPrefix, Arrays.copyOf(big, prefix),
                "prefix region was clobbered");
        Assertions.assertArrayEquals(reference, Arrays.copyOfRange(big, prefix, prefix + outLen),
                "output region is not the expected MAC");
        Assertions.assertFalse(
                Arrays.equals(reference, Arrays.copyOfRange(big, prefix - 1, prefix - 1 + outLen)),
                "MAC appears one byte before the requested offset");
    }

    @Test
    public void kmac_doFinal_aliased_tagAfterMessage() throws Exception
    {
        assertAliasedMacCorrect("KMAC-128", "KMAC-128", 40, null, new byte[]{9, 8, 7}, 40, 40, 40);
    }

    @Test
    public void kmac_doFinal_aliased_tagOverwritesMessageStart() throws Exception
    {
        assertAliasedMacCorrect("KMAC-128", "KMAC-128", 40, null, new byte[]{9, 8, 7}, 40, 40, 0);
    }

    @Test
    public void kmac_doFinal_aliased_tagMidMessage() throws Exception
    {
        assertAliasedMacCorrect("KMAC-256", "KMAC-256", 40, null, null, 40, 64, 16);
    }


    // Parameterised by MAC so GMAC - whose init additionally carries an IV -
    // gets the same whole-destination scrutiny as HMAC, rather than a
    // near-duplicate helper that could drift from it.
    private void assertAliasedMacCorrect(String macName, String function, int macLen,
                                         byte[] iv, int msgLen, int tagOff) throws Exception
    {
        assertAliasedMacCorrect(macName, function, macLen, iv, null, 0, msgLen, tagOff);
    }

    // Parameterised further for KMAC, which carries a customisation string and
    // a requested output length through the same init door as GMAC's IV.
    private void assertAliasedMacCorrect(String macName, String function, int macLen,
                                         byte[] iv, byte[] custom, int outLen,
                                         int msgLen, int tagOff) throws Exception
    {
        byte[] key = new byte[macName.startsWith("KMAC") ? 32 : macName.equals("HMAC") ? 32 : 16];
        byte[] msg = new byte[msgLen];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(msg);

        byte[] reference = new byte[macLen];
        long refA = macNI.allocateMac(macName, function);
        try
        {
            macNI.engineInit(refA, key, iv, custom, outLen);
            macNI.engineUpdate(refA, msg, 0, msg.length);
            Assertions.assertEquals(macLen, macNI.doFinal(refA, reference, 0));
        }
        finally
        {
            macNI.dispose(refA);
        }

        int cap = Math.max(msgLen, tagOff + macLen) + 8;
        byte[] buf = new byte[cap];
        RANDOM.nextBytes(buf);
        System.arraycopy(msg, 0, buf, 0, msgLen);
        byte[] snapshot = buf.clone();

        int written;
        long ref = macNI.allocateMac(macName, function);
        try
        {
            macNI.engineInit(ref, key, iv, custom, outLen);
            macNI.engineUpdate(ref, buf, 0, msgLen);
            written = macNI.doFinal(ref, buf, tagOff);
        }
        finally
        {
            macNI.dispose(ref);
        }

        String where = macName + " msgLen=" + msgLen + " tagOff=" + tagOff;
        Assertions.assertEquals(macLen, written, where + " tag length");
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
