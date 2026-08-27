/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.test.rsa.RSAKEMCipherTest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * RSA-KEM key transport through JSLFIPS - the whole {@link RSAKEMCipherTest}
 * contract re-run against the FIPS interface library and the FIPS
 * {@code OSSL_LIB_CTX}, plus the checks that only exist on the FIPS side.
 *
 * <p><b>This subclass is where the hard-coded {@code RSASVE} operation name is
 * actually load-bearing.</b> The base class cannot tell whether the name is set:
 * mainline defaults to RSASVE, so every test there passes either way. The
 * CMVP-validated 3.1.2 module does NOT default - it refuses
 * {@code EVP_PKEY_encapsulate}'s size query outright, and refuses it mutely
 * (measured: {@code fips-c-review/probes/rsakem_probe.c}). So running this
 * inherited suite against 3.1.2 is what proves the pin is present and correct;
 * remove it and 11 of these tests fail while the base class stays green.
 *
 * <p><b>Ungated.</b> RSASVE encapsulate/decapsulate works on both supported
 * modules at 2048 and 3072, under both fipsinstall configurations, so there is
 * no capability skip here - an absent service is a failure, not an absence.
 */
public class FIPSRSAKEMCipherTest
    extends RSAKEMCipherTest
{
    @BeforeAll
    static void beforeFips()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Override
    protected String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }

    /**
     * JSLFIPS and JSL must interoperate in both directions. They drive
     * different native libraries against different lib ctxs, so this is not
     * implied by either one agreeing with BouncyCastle separately.
     *
     * <p>Note which keys are used where. Since MT-14 NEITHER half of a keypair
     * crosses as an OBJECT, so each direction unwraps with the provider that
     * generated the pair, and the wrapping side re-decodes the peer's public
     * half through its own KeyFactory first. That is not a workaround: it is
     * what a CMS sender does anyway, since what it holds is an SPKI.
     */
    @Test
    public void interoperatesWithTheBaseProviderBothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("interoperatesWithTheBaseProviderBothDirections");
        KTSParameterSpec spec = kdf3Spec(256, randomBytes(sr, 12), NISTObjectIdentifiers.id_sha256);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, sr);
        SecretKey cek = kg.generateKey();

        // JSLFIPS wraps to a JSL public key; JSL unwraps with its own private
        // key. Since MT-14 the public key OBJECT does not cross providers: the
        // wrapping side re-decodes it through its OWN KeyFactory first, which
        // is what a real CMS sender does anyway (it has an SPKI, not a key
        // object) and is what puts the encapsulation in the module's library
        // rather than mainline's.
        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();

        byte[] a = wrap(JostleFIPSProvider.PROVIDER_NAME,
                FIPSTestUtil.crossPublic(jslKp.getPublic(), "RSA", JostleFIPSProvider.PROVIDER_NAME),
                spec, cek);
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(JostleProvider.PROVIDER_NAME, jslKp.getPrivate(), spec, a).getEncoded(),
                "JSLFIPS wrap -> JSL unwrap");

        // ...and the reverse, against a JSLFIPS-generated pair.
        KeyPair fipsKp = keyPair();
        byte[] b = wrap(JostleProvider.PROVIDER_NAME,
                FIPSTestUtil.crossPublic(fipsKp.getPublic(), "RSA", JostleProvider.PROVIDER_NAME),
                spec, cek);
        Assertions.assertArrayEquals(cek.getEncoded(),
                unwrap(JostleFIPSProvider.PROVIDER_NAME, fipsKp.getPrivate(), spec, b).getEncoded(),
                "JSL wrap -> JSLFIPS unwrap");
    }

    /**
     * Key isolation on BOTH halves: neither a JSL private key nor a JSL public
     * key may be used through the JSLFIPS cipher. The public half was accepted
     * until MT-14 Phase 2, on the premise that public material carries no
     * secret - true, but beside the point, because the operation was then
     * served by the key's own provider and so ran outside the module. See
     * testing.md "JSL &lt;-&gt; JSLFIPS key sharing".
     */
    @Test
    public void jslPrivateKeyRefusedForUnwrap() throws Exception
    {
        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();

        Cipher u = Cipher.getInstance(XFORM, JostleFIPSProvider.PROVIDER_NAME);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> u.init(Cipher.UNWRAP_MODE, jslKp.getPrivate(),
                        kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256)));
        Assertions.assertEquals(
                "private key was created by a different Jostle provider instance; encode it with getEncoded() and decode it through this provider's KeyFactory",
                e.getMessage());

        // ...and its PUBLIC half is refused too, with the matching message.
        Cipher w = Cipher.getInstance(XFORM, JostleFIPSProvider.PROVIDER_NAME);
        InvalidKeyException pub = Assertions.assertThrows(InvalidKeyException.class,
                () -> w.init(Cipher.WRAP_MODE, jslKp.getPublic(),
                        kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256)));
        Assertions.assertEquals(
                "public key was created by a different Jostle provider instance; encode it "
                        + "with getEncoded() and decode it through this provider's KeyFactory",
                pub.getMessage());

        // The sanctioned crossing works: re-decode the public half through
        // JSLFIPS's own KeyFactory and the wrap succeeds.
        Cipher ok = Cipher.getInstance(XFORM, JostleFIPSProvider.PROVIDER_NAME);
        Assertions.assertDoesNotThrow(() -> ok.init(Cipher.WRAP_MODE,
                FIPSTestUtil.crossPublic(jslKp.getPublic(), "RSA", JostleFIPSProvider.PROVIDER_NAME),
                kdf3Spec(256, null, NISTObjectIdentifiers.id_sha256)));
    }

    /**
     * The RSA keymgmt behind the KEM is the FIPS module's, not mainline's.
     * <p>
     * Mainline implements RSASVE identically, so no agreement, round-trip or
     * negative test above can tell the two apart - asking OpenSSL which
     * provider implements it is the only check that can. The ChaCha20 row is
     * the control: the probe must be able to answer something other than
     * {@code "fips"}, or a stub returning it would pass.
     */
    @Test
    public void rsaIsImplementedByTheFipsModule()
    {
        FIPSTestUtil.assumeFipsProvider();

        Assertions.assertEquals("fips",
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_KEYMGMT, "RSA"),
                "the RSA keymgmt behind RSA-KEM must be the module's");
        Assertions.assertNull(
                FIPSNISelector.OpenSSLFIPSNI.implementingProvider(OpenSSLFIPSNI.OP_CIPHER, "ChaCha20"),
                "control: the probe must be able to answer something other than \"fips\"");
    }
}
