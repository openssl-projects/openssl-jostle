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

package org.openssl.jostle.test.parity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * Divergences from BouncyCastle that are DELIBERATE, pinned in both halves.
 *
 * <p>The standing rule is to match BouncyCastle's exception type for the same
 * refusal, because callers write their catch blocks against BC. It has one
 * boundary, added after the MT-31 survey measured two cases where BC is the
 * non-canonical side: <b>match BouncyCastle UNLESS BouncyCastle diverges from
 * the JCE contract.</b> Where BC is wrong, JCE-canonical usually wins and the
 * divergence is pinned here.
 *
 * <p><b>"Usually" became load-bearing on 2026-09-13, so read it before adding
 * a cell.</b> The boundary is a default, not a law: where following the
 * contract would break callers written against BouncyCastle, the ruling can go
 * the other way. D5 (Megan, 2026-09-13) takes us WITH BouncyCastle and AGAINST
 * the JCE contract at KeyAgreement's pre-doPhase surface — see
 * {@link #ecdhGenerateSecretBeforeDoPhase_followsBouncyCastleAgainstTheContract}.
 *
 * <p>So this file holds divergences in BOTH directions, and every cell must say
 * which side is canonical and which side we took. A cell recording only "we
 * differ from BC" does not belong here — the reason is the whole content.
 *
 * <p><b>Both halves are asserted deliberately.</b> A pin that recorded only our
 * type would let a future BC-parity sweep "fix" the divergence without ever
 * meeting the reason it exists. Asserting BC's half too means such a sweep must
 * first delete a test that explains itself.
 *
 * <p><b>The BC half is measured LIVE, and a bcprov bump that moves BC will fail
 * this loudly. That is the pin's second job, not fragility</b> - if the
 * reference moves we want to know, because the reason for the divergence may
 * have moved with it.
 */
public class ExceptionTypeDivergencePinTest
{
    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static Throwable initWith(String provider, java.security.Key key,
                                      java.security.spec.AlgorithmParameterSpec ps)
    {
        try
        {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
            c.init(Cipher.ENCRYPT_MODE, key, ps);
            return null;
        }
        catch (Throwable t)
        {
            return t;
        }
    }

    /**
     * A short key is an InvalidKeyException for us and an
     * InvalidAlgorithmParameterException for BouncyCastle.
     *
     * <p>We are the JCE-canonical side: {@code InvalidKeyException} is the type
     * the contract names for a bad key, and it is also what triggers the JCE's
     * next-provider fallback. BC reports it as a parameter problem because its
     * key-length check happens inside its parameter handling - both messages
     * name the key length, so the disagreement is about the TYPE, not about
     * what was wrong.
     *
     * <p>Matching BC here would make us less correct, so we do not.
     */
    @Test
    public void shortKey_weAreJceCanonicalAndBouncyCastleIsNot()
    {
        byte[] shortKey = new byte[15];          // one byte under AES-128
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);

        Throwable ours = initWith(JostleProvider.PROVIDER_NAME,
                new SecretKeySpec(shortKey, "AES"), iv);
        Throwable bc = initWith(BouncyCastleProvider.PROVIDER_NAME,
                new SecretKeySpec(shortKey, "AES"), iv);

        Assertions.assertNotNull(ours, "a 15-byte AES key must be refused");
        Assertions.assertNotNull(bc, "BouncyCastle must refuse it too");

        Assertions.assertEquals(InvalidKeyException.class, ours.getClass(),
                "ours must stay the JCE-canonical type for a bad key");
        Assertions.assertEquals(InvalidAlgorithmParameterException.class, bc.getClass(),
                "BouncyCastle's half of the pin: if this fails, BC has MOVED -"
                        + " re-evaluate whether the divergence still has a reason");
    }

    /**
     * An unrelated AlgorithmParameterSpec is refused by us and silently ignored
     * by BouncyCastle.
     *
     * <p>A decision divergence, not a type one, and it is decided in our Java
     * layer rather than in OpenSSL - so the OpenSSL-wins rule does not dispose
     * of it. We keep ours: silently discarding a caller's parameters is worse
     * than refusing them, because the caller believes they took effect.
     */
    @Test
    public void foreignParameterSpec_weRefuseWhereBouncyCastleIgnores()
    {
        byte[] key = new byte[16];
        PBEParameterSpec foreign = new PBEParameterSpec(new byte[8], 1000);

        Throwable ours = initWith(JostleProvider.PROVIDER_NAME,
                new SecretKeySpec(key, "AES"), foreign);
        Throwable bc = initWith(BouncyCastleProvider.PROVIDER_NAME,
                new SecretKeySpec(key, "AES"), foreign);

        Assertions.assertNotNull(ours, "a PBEParameterSpec on AES must be refused");
        Assertions.assertEquals(InvalidAlgorithmParameterException.class, ours.getClass(),
                "ours must be the JCE-canonical parameter refusal");
        Assertions.assertNull(bc,
                "BouncyCastle's half of the pin: it ACCEPTS the foreign spec."
                        + " If this fails, BC has started refusing and the"
                        + " divergence may be over");
    }

    // -----------------------------------------------------------------
    // D5 — KeyAgreement before doPhase. Here the ruling takes us WITH
    // BouncyCastle and AGAINST the JCE contract.
    // -----------------------------------------------------------------

    /** One call against a freshly initialised, un-phased KeyAgreement. */
    private interface Call
    {
        Object apply(KeyAgreement ka) throws Exception;
    }

    /**
     * Describes the OUTCOME of one call rather than asserting inside the
     * sweep, so ours and BouncyCastle's can be compared as data.
     */
    private static String outcome(String provider, String agreement, PrivateKey key, Call call)
            throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(agreement, provider);
        ka.init(key);
        try
        {
            Object v = call.apply(ka);
            return v == null ? "returned null" : "returned " + v.getClass().getName();
        }
        catch (Throwable t)
        {
            return "threw " + t.getClass().getName();
        }
    }

    /**
     * The four generateSecret shapes, each driven on its own instance because
     * the first call would otherwise decide the state the next one meets.
     * The undersized buffer is the third: the contract specifies
     * ShortBufferException for it, which makes it the sharpest of the four.
     */
    private static String[] sweepBeforeDoPhase(String provider, String agreement, PrivateKey key)
            throws Exception
    {
        return sweepBeforeDoPhase(provider, agreement, key, "AES");
    }

    /**
     * As above, with the terminal call's algorithm named. OUR KDF agreements
     * size their key from a CMS wrap OID and refuse the bare name "AES";
     * BouncyCastle sizes it (measured: 32 bytes after doPhase, on the HKDF and
     * raw agreements alike). So a cell covering one of ours passes the OID
     * instead — the shape being pinned is the pre-doPhase refusal, and a name
     * only our side refuses would measure our lookup rather than the state.
     */
    private static String[] sweepBeforeDoPhase(String provider, String agreement, PrivateKey key,
            String terminalAlgorithm)
            throws Exception
    {
        return new String[]{
                outcome(provider, agreement, key, ka -> ka.generateSecret()),
                outcome(provider, agreement, key, ka -> ka.generateSecret(new byte[256], 0)),
                outcome(provider, agreement, key, ka -> ka.generateSecret(new byte[1], 0)),
                outcome(provider, agreement, key, ka -> ka.generateSecret(terminalAlgorithm))};
    }

    /** What BOTH providers do, and what the JCE contract says instead. */
    private static final String[] BC_PRE_DOPHASE = {
            "returned null",
            "threw java.lang.NullPointerException",
            "threw java.lang.NullPointerException",
            "threw java.lang.NullPointerException"};

    private static void assertFollowsBouncyCastle(String agreement, PrivateKey ours, PrivateKey theirs)
            throws Exception
    {
        Assertions.assertArrayEquals(BC_PRE_DOPHASE,
                sweepBeforeDoPhase(JostleProvider.PROVIDER_NAME, agreement, ours),
                agreement + ": ours must follow BouncyCastle, contract notwithstanding");
        Assertions.assertArrayEquals(BC_PRE_DOPHASE,
                sweepBeforeDoPhase(BouncyCastleProvider.PROVIDER_NAME, agreement, theirs),
                agreement + ": BouncyCastle's half of the pin. If this fails BC has MOVED,"
                        + " and following it against the contract may no longer be the ruling");
    }

    /**
     * ECDH generateSecret before doPhase: we follow BouncyCastle, deliberately
     * against the JCE contract. D5, ruled by Megan on 2026-09-13.
     *
     * <p>The contract says {@code IllegalStateException} from every overload,
     * and {@code ShortBufferException} where the buffer is too small. Measured
     * on BC 1.86, none of that happens: {@code generateSecret()} returns null,
     * and the other three raise a raw {@code NullPointerException} — the
     * undersized buffer included, because BC dereferences the secret it never
     * derived before it ever reaches its length check.
     *
     * <p><b>This is the file's first cell where the ruling goes WITH BC and
     * against the contract.</b> Ruled D5 = option 2 by Megan on 2026-09-13;
     * she did not state a rationale, and none is invented here.
     *
     * <p>What can be said is the BOUND, because it was measured: every outcome
     * at this surface is a refusal either way, so no wrong bytes reach a
     * caller. That bound is specific to this surface and does not generalise:
     * it is what makes following the reference tolerable here, and nowhere
     * else.
     *
     */
    @Test
    public void ecdhGenerateSecretBeforeDoPhase_followsBouncyCastleAgainstTheContract()
            throws Exception
    {
        KeyPairGenerator ourKpg =
                KeyPairGenerator.getInstance("EC", JostleProvider.PROVIDER_NAME);
        ourKpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPairGenerator bcKpg =
                KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        bcKpg.initialize(new ECGenParameterSpec("P-256"));

        assertFollowsBouncyCastle("ECDH",
                ourKpg.generateKeyPair().getPrivate(),
                bcKpg.generateKeyPair().getPrivate());
    }

    /**
     * The XDH half of D5, identical in shape to the ECDH cell above. Both are
     * pinned because the two SPIs are separate classes: a fix applied to one
     * and not the other is exactly the drift this file exists to catch.
     */
    @Test
    public void xdhGenerateSecretBeforeDoPhase_followsBouncyCastleAgainstTheContract()
            throws Exception
    {
        PrivateKey ours = KeyPairGenerator
                .getInstance("X25519", JostleProvider.PROVIDER_NAME)
                .generateKeyPair().getPrivate();
        PrivateKey theirs = KeyPairGenerator
                .getInstance("X25519", BouncyCastleProvider.PROVIDER_NAME)
                .generateKeyPair().getPrivate();

        assertFollowsBouncyCastle("X25519", ours, theirs);
    }

    /**
     * DH generateSecret before doPhase: we refuse on every overload.
     *
     * <p>{@code IllegalStateException} is the type the JCE contract specifies
     * for a terminal call made before the agreement has a peer key.
     */
    @Test
    public void dhGenerateSecretBeforeDoPhase_isRefusedOnEveryOverload()
            throws Exception
    {
        KeyPair ourKp = KeyPairGenerator
                .getInstance("DH", JostleProvider.PROVIDER_NAME).generateKeyPair();

        String[] refusedEverywhere = {
                "threw java.lang.IllegalStateException",
                "threw java.lang.IllegalStateException",
                "threw java.lang.IllegalStateException",
                "threw java.lang.IllegalStateException"};
        Assertions.assertArrayEquals(refusedEverywhere,
                sweepBeforeDoPhase(JostleProvider.PROVIDER_NAME, "DH", ourKp.getPrivate()),
                "ours must refuse every overload with the contract's type");
    }

    /**
     * RFC 8418 HKDF agreement before doPhase, and it does NOT follow the raw
     * XDH cell above — adding a KDF changes what BouncyCastle does.
     *
     * <p>Its raw path returns null; its KDF path dereferences the absent secret
     * to size the key, so {@code generateSecret()} and the two buffer forms
     * raise {@code NullPointerException}, and the named form reaches
     * BouncyCastle's HKDF parameter check first and raises
     * {@code IllegalArgumentException}. Three of the four shapes therefore
     * differ from the raw agreement's, which is why this is its own cell rather
     * than another algorithm in the sweep.
     *
     * <p>The terminal call names a CMS wrap OID, not the bare "AES" the shared
     * sweep uses: our KDF agreements size their key from the OID and refuse the
     * bare name, which BouncyCastle accepts. "AES" would therefore measure our
     * lookup instead of the state.
     */
    @Test
    public void hkdfAgreementBeforeDoPhase_followsBouncyCastlesKdfPath()
            throws Exception
    {
        String agreement = "XDHwithSHA256HKDF";
        String aes256Wrap = "2.16.840.1.101.3.4.1.45";

        KeyPair ourKp = KeyPairGenerator
                .getInstance("X25519", JostleProvider.PROVIDER_NAME).generateKeyPair();
        KeyPair theirKp = KeyPairGenerator
                .getInstance("X25519", BouncyCastleProvider.PROVIDER_NAME).generateKeyPair();

        String[] bcKdfPath = {
                "threw java.lang.NullPointerException",
                "threw java.lang.NullPointerException",
                "threw java.lang.NullPointerException",
                "threw java.lang.IllegalArgumentException"};

        Assertions.assertArrayEquals(bcKdfPath,
                sweepBeforeDoPhase(JostleProvider.PROVIDER_NAME, agreement,
                        ourKp.getPrivate(), aes256Wrap),
                agreement + ": ours must follow BouncyCastle's KDF path");
        Assertions.assertArrayEquals(bcKdfPath,
                sweepBeforeDoPhase(BouncyCastleProvider.PROVIDER_NAME, agreement,
                        theirKp.getPrivate(), aes256Wrap),
                agreement + ": BouncyCastle's half of the pin. If this fails BC has MOVED,"
                        + " and following it may no longer be the ruling");
    }

    /**
     * A mismatched XDH peer key: InvalidKeyException for us, a raw
     * {@code ClassCastException} for BouncyCastle.
     *
     * <p>We are the JCE-canonical side. {@code doPhase} declares
     * {@code InvalidKeyException} and a caller cannot reasonably be asked to
     * catch a ClassCastException from a key-agreement call — it is unchecked,
     * so it escapes to whatever sits above. BC reaches the cast because it
     * resolves the peer to its own parameter type without checking the curve
     * first.
     *
     * <p>Measured on BC 1.86: an X448 public key into an X25519 agreement
     * gives {@code X448PublicKeyParameters cannot be cast to
     * X25519PublicKeyParameters}. BC's ECDH path does NOT have this problem —
     * it raises an InvalidKeyException subclass there and we agree with it, so
     * the divergence is specific to XDH.
     */
    @Test
    public void xdhMismatchedPeer_weAreJceCanonicalWhereBouncyCastleRaisesClassCastException()
            throws Exception
    {
        for (String provider : new String[]{
                JostleProvider.PROVIDER_NAME, BouncyCastleProvider.PROVIDER_NAME})
        {
            KeyPair local = KeyPairGenerator.getInstance("X25519", provider).generateKeyPair();
            java.security.PublicKey peer = KeyPairGenerator
                    .getInstance("X448", provider).generateKeyPair().getPublic();

            KeyAgreement ka = KeyAgreement.getInstance("X25519", provider);
            ka.init(local.getPrivate());

            Throwable t = Assertions.assertThrows(Throwable.class,
                    () -> ka.doPhase(peer, true),
                    provider + ": an X448 peer into an X25519 agreement must be refused");

            if (JostleProvider.PROVIDER_NAME.equals(provider))
            {
                Assertions.assertTrue(t instanceof InvalidKeyException,
                        "ours must be the JCE-canonical type doPhase declares, got "
                                + t.getClass().getName());
            }
            else
            {
                Assertions.assertEquals(ClassCastException.class, t.getClass(),
                        "BouncyCastle's half of the pin: an unchecked ClassCastException."
                                + " If this fails, BC has started refusing typed and the"
                                + " divergence may be over");
            }
        }
    }
}
