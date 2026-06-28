/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ks;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class KSServiceSPI
    extends KeyStoreSpi
{
    private static final KSServiceNI ksServiceNI = NISelector.KSServiceNI;
    private static final byte[] PKCS12_AUTH_SAFE_DATA_OID = new byte[] {
            0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01,
            0x07, 0x01
    };

    // Store-time algorithm profile selectors (mirror interface/util/ks.h).
    private static final int PBE_3DES = 1;
    private static final int PBE_AES128_CBC = 2;
    private static final int PBE_AES256_CBC = 3;
    private static final int MAC_TRADITIONAL = 1;
    private static final int MAC_PBMAC1 = 2;
    private static final int MD_SHA1 = 1;
    private static final int MD_SHA256 = 2;
    private static final int MD_SHA512 = 3;
    private static final int PBE_ITERATIONS = 600000;
    private static final int MAC_ITERATIONS = 600000;
    private static final int PBMAC1_ITERATIONS = 65536;

    // The native ks_ctx is a plain PKCS#12 container; the JCA type name only
    // selects the store-time algorithm profile, so allocation always uses the
    // canonical base type.
    private static final String BASE_TYPE = "PKCS12";

    private final KSReference ref;

    // Store-time algorithm profile, selected per registered JCA type name (see
    // ProvKS). Default-provider algorithms only (no RC2), so BouncyCastle's
    // RC2-cert legacy default is not reproduced; bare "PKCS12" is a modern AES
    // profile rather than BC's legacy default.
    private final int keyPbe;
    private final int certPbe;
    private final int macScheme;
    private final int macDigest;
    private final int pbeIter;
    private final int macIter;

    // KeyStore SPIs receive no SecureRandom from the JCE API, so the store path
    // sources entropy from a cached default RandSource (PKCS#12 salts need no
    // special strength; load/verify consume no entropy at all).
    private final RandSource randSource = DefaultRandSource.replaceWith(null, null, 128);

    public KSServiceSPI()
    {
        // Bare PKCS12: modern default -- AES-256-CBC keys, AES-128-CBC certs
        // (PBES2 / PBKDF2-HMAC-SHA256), HMAC-SHA256 integrity MAC.
        this(PBE_AES256_CBC, PBE_AES128_CBC, MAC_TRADITIONAL, MD_SHA256,
                PBE_ITERATIONS, MAC_ITERATIONS);
    }

    protected KSServiceSPI(int keyPbe, int certPbe, int macScheme, int macDigest,
                           int pbeIter, int macIter)
    {
        this.ref = new KSReference(ksServiceNI.allocateKeyStore(BASE_TYPE), BASE_TYPE);
        this.keyPbe = keyPbe;
        this.certPbe = certPbe;
        this.macScheme = macScheme;
        this.macDigest = macDigest;
        this.pbeIter = pbeIter;
        this.macIter = macIter;
    }

    /**
     * Legacy profile, matching BouncyCastle's {@code PKCS12-3DES-3DES}: 3DES
     * keys and certs under a traditional HMAC-SHA1 MAC (max old-reader compat).
     */
    public static final class PKCS12_3DES_3DES
        extends KSServiceSPI
    {
        public PKCS12_3DES_3DES()
        {
            super(PBE_3DES, PBE_3DES, MAC_TRADITIONAL, MD_SHA1,
                    PBE_ITERATIONS, MAC_ITERATIONS);
        }
    }

    /**
     * AES-256-CBC keys + AES-128-CBC certs (PBES2 / PBKDF2-HMAC-SHA256) under a
     * traditional HMAC-SHA256 MAC.
     */
    public static final class PKCS12_AES256_AES128
        extends KSServiceSPI
    {
        public PKCS12_AES256_AES128()
        {
            super(PBE_AES256_CBC, PBE_AES128_CBC, MAC_TRADITIONAL, MD_SHA256,
                    PBE_ITERATIONS, MAC_ITERATIONS);
        }
    }

    /**
     * RFC 9579 PBMAC1 (HMAC-SHA512 over PBKDF2-HMAC-SHA256) over AES-256/AES-128
     * content, matching BouncyCastle's {@code PKCS12-PBMAC1}.
     */
    public static final class PKCS12_PBMAC1
        extends KSServiceSPI
    {
        public PKCS12_PBMAC1()
        {
            super(PBE_AES256_CBC, PBE_AES128_CBC, MAC_PBMAC1, MD_SHA512,
                    PBE_ITERATIONS, PBMAC1_ITERATIONS);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }

        byte[] encoded = null;
        byte[] encodedPassword = encodePassword(password);
        try
        {
            synchronized (this)
            {
                encoded = ksServiceNI.getKey(ref.getReference(), alias,
                        encodedPassword);
            }
            if (encoded == null)
            {
                return null;
            }
            return generatePrivateKey(encoded);
        }
        catch (KeyStoreException | InvalidKeySpecException e)
        {
            throw new UnrecoverableKeyException(e.getMessage());
        }
        finally
        {
            if (encoded != null)
            {
                Arrays.fill(encoded, (byte) 0);
            }
            if (encodedPassword != null)
            {
                Arrays.fill(encodedPassword, (byte) 0);
            }
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }

        try
        {
            byte[] encoded;
            synchronized (this)
            {
                encoded = ksServiceNI.getCertificateChain(ref.getReference(), alias);
            }
            return decodeCertificateChain(encoded);
        }
        catch (KeyStoreException | CertificateException | IOException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias)
    {
        Certificate[] chain = engineGetCertificateChain(alias);
        return chain == null || chain.length == 0 ? null : chain[0];
    }

    @Override
    public Date engineGetCreationDate(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }

        synchronized (this)
        {
            if (!ksServiceNI.containsAlias(ref.getReference(), alias))
            {
                return null;
            }
            try
            {
                return new Date(ksServiceNI.getCreationDate(ref.getReference(), alias));
            }
            catch (KeyStoreException e)
            {
                throw new IllegalStateException(e.getMessage(), e);
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
        throws KeyStoreException
    {
        if (alias == null)
        {
            throw new KeyStoreException("alias is null");
        }
        if (key == null)
        {
            throw new KeyStoreException("key is null");
        }
        if (!(key instanceof PrivateKey))
        {
            throw new KeyStoreException("only private key entries are supported");
        }
        if (!"PKCS#8".equalsIgnoreCase(key.getFormat()))
        {
            throw new KeyStoreException("private key must use PKCS#8 encoding");
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new KeyStoreException("private key encoding is null");
        }

        byte[] encodedPassword = encodePassword(password);
        byte[] encodedChain;
        try
        {
            encodedChain = encodeCertificateChain(chain);
            synchronized (this)
            {
                ksServiceNI.setKey(ref.getReference(), alias, encoded,
                        encodedPassword);
                ksServiceNI.setCertificateChain(ref.getReference(), alias, encodedChain);
            }
        }
        catch (CertificateEncodingException e)
        {
            KeyStoreException kse =
                    new KeyStoreException("unable to encode certificate chain");
            kse.initCause(e);
            throw kse;
        }
        finally
        {
            Arrays.fill(encoded, (byte) 0);
            if (encodedPassword != null)
            {
                Arrays.fill(encodedPassword, (byte) 0);
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
        throws KeyStoreException
    {
        if (alias == null)
        {
            throw new KeyStoreException("alias is null");
        }
        if (key == null)
        {
            throw new KeyStoreException("key encoding is null");
        }

        byte[] encodedChain;
        try
        {
            encodedChain = encodeCertificateChain(chain);
        }
        catch (CertificateEncodingException e)
        {
            KeyStoreException kse =
                    new KeyStoreException("unable to encode certificate chain");
            kse.initCause(e);
            throw kse;
        }

        synchronized (this)
        {
            ksServiceNI.setKey(ref.getReference(), alias, key, null);
            ksServiceNI.setCertificateChain(ref.getReference(), alias, encodedChain);
        }
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert)
        throws KeyStoreException
    {
        if (alias == null)
        {
            throw new KeyStoreException("alias is null");
        }
        if (cert == null)
        {
            throw new KeyStoreException("certificate is null");
        }

        synchronized (this)
        {
            if (ksServiceNI.isKeyEntry(ref.getReference(), alias))
            {
                throw new KeyStoreException("alias identifies a key entry");
            }
            try
            {
                ksServiceNI.setCertificateEntry(ref.getReference(), alias,
                        cert.getEncoded());
            }
            catch (CertificateEncodingException e)
            {
                KeyStoreException kse =
                        new KeyStoreException("unable to encode certificate");
                kse.initCause(e);
                throw kse;
            }
        }
    }

    @Override
    public void engineDeleteEntry(String alias)
        throws KeyStoreException
    {
        if (alias == null)
        {
            throw new KeyStoreException("alias is null");
        }
        synchronized (this)
        {
            ksServiceNI.deleteEntry(ref.getReference(), alias);
        }
    }

    @Override
    public Enumeration<String> engineAliases()
    {
        try
        {
            synchronized (this)
            {
                return Collections.enumeration(
                        decodeAliases(ksServiceNI.getAliases(ref.getReference())));
            }
        }
        catch (KeyStoreException | IOException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }

        synchronized (this)
        {
            return ksServiceNI.containsAlias(ref.getReference(), alias);
        }
    }

    @Override
    public int engineSize()
    {
        synchronized (this)
        {
            return ksServiceNI.size(ref.getReference());
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }

        synchronized (this)
        {
            return ksServiceNI.isKeyEntry(ref.getReference(), alias);
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }

        synchronized (this)
        {
            return ksServiceNI.isCertificateEntry(ref.getReference(), alias);
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert)
    {
        if (cert == null)
        {
            return null;
        }

        try
        {
            byte[] encoded = cert.getEncoded();
            Enumeration<String> aliases = engineAliases();
            while (aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                Certificate candidate = engineGetCertificate(alias);
                if (candidate != null
                        && Arrays.areEqual(encoded, candidate.getEncoded()))
                {
                    return alias;
                }
            }
            return null;
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (stream == null)
        {
            throw new IOException("output stream is null");
        }

        synchronized (this)
        {
            byte[] encodedPassword = encodePassword(password);
            try
            {
                stream.write(ksServiceNI.store(ref.getReference(), encodedPassword,
                        keyPbe, certPbe, macScheme, macDigest, pbeIter, macIter, randSource));
            }
            finally
            {
                if (encodedPassword != null)
                {
                    Arrays.fill(encodedPassword, (byte) 0);
                }
            }
        }
    }

    @Override
    public void engineStore(KeyStore.LoadStoreParameter param)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (!(param instanceof StreamLoadStoreParameter))
        {
            throw new IllegalArgumentException(
                    "StreamLoadStoreParameter required for store");
        }

        StreamLoadStoreParameter streamParam = (StreamLoadStoreParameter)param;
        if (streamParam.getOutputStream() == null)
        {
            throw new IllegalArgumentException("output stream is required");
        }
        engineStore(streamParam.getOutputStream(),
                passwordFromProtection(streamParam.getProtectionParameter()));
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        byte[] input = null;
        if (stream != null)
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = stream.read(buffer)) >= 0)
            {
                out.write(buffer, 0, read);
            }
            input = out.toByteArray();
        }

        synchronized (this)
        {
            byte[] encodedPassword = encodePassword(password);
            try
            {
                ksServiceNI.load(ref.getReference(), input, encodedPassword);
            }
            finally
            {
                if (encodedPassword != null)
                {
                    Arrays.fill(encodedPassword, (byte) 0);
                }
            }
        }
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter param)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        InputStream stream = null;
        KeyStore.ProtectionParameter protection = null;
        if (param instanceof StreamLoadStoreParameter)
        {
            StreamLoadStoreParameter streamParam = (StreamLoadStoreParameter)param;
            stream = streamParam.getInputStream();
            protection = streamParam.getProtectionParameter();
        }
        else if (param != null)
        {
            protection = param.getProtectionParameter();
        }
        engineLoad(stream, passwordFromProtection(protection));
    }

    public Set<KeyStore.Entry.Attribute> engineGetAttributes(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias must not be null");
        }
        return Collections.emptySet();
    }

    @Override
    public KeyStore.Entry engineGetEntry(String alias,
                                         KeyStore.ProtectionParameter protParam)
        throws KeyStoreException, NoSuchAlgorithmException,
        UnrecoverableEntryException
    {
        if (!engineContainsAlias(alias))
        {
            return null;
        }

        if (engineIsCertificateEntry(alias))
        {
            if (protParam instanceof KeyStore.PasswordProtection
                    && ((KeyStore.PasswordProtection)protParam).getPassword() != null)
            {
                throw new UnrecoverableEntryException(
                        "trusted certificate entries are not password-protected");
            }
            return new KeyStore.TrustedCertificateEntry(engineGetCertificate(alias));
        }

        if (!engineIsKeyEntry(alias))
        {
            return null;
        }
        if (!(protParam instanceof KeyStore.PasswordProtection))
        {
            throw new UnrecoverableKeyException(
                    "requested entry requires a password");
        }

        KeyStore.PasswordProtection passwordProtection =
                (KeyStore.PasswordProtection)protParam;
        if (passwordProtection.getProtectionAlgorithm() != null)
        {
            throw new KeyStoreException(
                    "unsupported password protection algorithm");
        }

        Key key = engineGetKey(alias, passwordProtection.getPassword());
        if (key == null)
        {
            return null;
        }
        if (!(key instanceof PrivateKey))
        {
            throw new UnrecoverableEntryException(
                    "only private key entries are supported");
        }

        Certificate[] chain = engineGetCertificateChain(alias);
        if (chain == null || chain.length == 0)
        {
            throw new UnrecoverableEntryException(
                    "private key entry does not contain a certificate chain");
        }
        return new KeyStore.PrivateKeyEntry((PrivateKey)key, chain);
    }

    @Override
    public void engineSetEntry(String alias, KeyStore.Entry entry,
                               KeyStore.ProtectionParameter protParam)
        throws KeyStoreException
    {
        if (alias == null)
        {
            throw new KeyStoreException("alias is null");
        }
        if (entry == null)
        {
            throw new KeyStoreException("entry is null");
        }

        if (entry instanceof KeyStore.TrustedCertificateEntry)
        {
            if (protParam instanceof KeyStore.PasswordProtection
                    && ((KeyStore.PasswordProtection)protParam).getPassword() != null)
            {
                throw new KeyStoreException(
                        "trusted certificate entries are not password-protected");
            }
            engineSetCertificateEntry(alias,
                    ((KeyStore.TrustedCertificateEntry)entry).getTrustedCertificate());
            return;
        }

        if (entry instanceof KeyStore.PrivateKeyEntry)
        {
            if (!(protParam instanceof KeyStore.PasswordProtection))
            {
                throw new KeyStoreException(
                        "password required to create PrivateKeyEntry");
            }
            KeyStore.PasswordProtection passwordProtection =
                    (KeyStore.PasswordProtection)protParam;
            if (passwordProtection.getProtectionAlgorithm() != null)
            {
                throw new KeyStoreException(
                        "unsupported password protection algorithm");
            }
            if (passwordProtection.getPassword() == null)
            {
                throw new KeyStoreException(
                        "non-null password required to create PrivateKeyEntry");
            }
            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry)entry;
            engineSetKeyEntry(alias, privateKeyEntry.getPrivateKey(),
                    passwordProtection.getPassword(),
                    privateKeyEntry.getCertificateChain());
            return;
        }

        throw new KeyStoreException(
                "unsupported entry type: " + entry.getClass().getName());
    }

    @Override
    public boolean engineEntryInstanceOf(String alias,
                                         Class<? extends KeyStore.Entry> entryClass)
    {
        if (entryClass == null)
        {
            throw new NullPointerException("entry class must not be null");
        }
        if (entryClass == KeyStore.TrustedCertificateEntry.class)
        {
            return engineIsCertificateEntry(alias);
        }
        if (entryClass == KeyStore.PrivateKeyEntry.class)
        {
            return engineIsKeyEntry(alias) && engineGetCertificate(alias) != null;
        }
        return false;
    }

    public boolean engineProbe(InputStream stream)
        throws IOException
    {
        if (stream == null)
        {
            throw new NullPointerException("input stream must not be null");
        }

        try
        {
            DataInputStream dataStream = stream instanceof DataInputStream
                    ? (DataInputStream)stream : new DataInputStream(stream);
            if (dataStream.readUnsignedByte() != 0x30)
            {
                return false;
            }
            readAsn1Length(dataStream);
            if (dataStream.readUnsignedByte() != 0x02)
            {
                return false;
            }
            int versionLength = readAsn1Length(dataStream);
            if (versionLength != 1 || dataStream.readUnsignedByte() != 0x03)
            {
                return false;
            }
            if (dataStream.readUnsignedByte() != 0x30)
            {
                return false;
            }
            readAsn1Length(dataStream);
            if (dataStream.readUnsignedByte() != 0x06)
            {
                return false;
            }
            int oidLength = readAsn1Length(dataStream);
            if (oidLength != PKCS12_AUTH_SAFE_DATA_OID.length)
            {
                return false;
            }
            byte[] oid = new byte[oidLength];
            dataStream.readFully(oid);
            return Arrays.areEqual(PKCS12_AUTH_SAFE_DATA_OID, oid);
        }
        catch (EOFException e)
        {
            return false;
        }
    }

    public static final class StreamLoadStoreParameter
        implements KeyStore.LoadStoreParameter
    {
        private final InputStream inputStream;
        private final OutputStream outputStream;
        private final KeyStore.ProtectionParameter protectionParameter;

        public StreamLoadStoreParameter(InputStream inputStream,
                                        KeyStore.ProtectionParameter protectionParameter)
        {
            this(inputStream, null, protectionParameter);
        }

        public StreamLoadStoreParameter(OutputStream outputStream,
                                        KeyStore.ProtectionParameter protectionParameter)
        {
            this(null, outputStream, protectionParameter);
        }

        public StreamLoadStoreParameter(InputStream inputStream,
                                        OutputStream outputStream,
                                        KeyStore.ProtectionParameter protectionParameter)
        {
            this.inputStream = inputStream;
            this.outputStream = outputStream;
            this.protectionParameter = protectionParameter;
        }

        public InputStream getInputStream()
        {
            return inputStream;
        }

        public OutputStream getOutputStream()
        {
            return outputStream;
        }

        @Override
        public KeyStore.ProtectionParameter getProtectionParameter()
        {
            return protectionParameter;
        }
    }

    private static class Disposer
        extends NativeDisposer
    {
        Disposer(long ref)
        {
            super(ref);
        }

        @Override
        protected void dispose(long reference)
        {
            ksServiceNI.dispose(reference);
        }
    }

    private static class KSReference
        extends NativeReference
    {
        KSReference(long reference, String name)
        {
            super(reference, name);
        }

        @Override
        protected Runnable createAction()
        {
            return new Disposer(reference);
        }
    }

    private static PrivateKey generatePrivateKey(byte[] encoded)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PKEYKeySpec spec = ASN1Encoder.fromPrivateKeyInfo(encoded, 0, encoded.length);
        String algorithm = keyFactoryAlgorithm(spec.getType());
        try
        {
            return KeyFactory.getInstance(algorithm, JostleProvider.PROVIDER_NAME)
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        }
        catch (NoSuchProviderException e)
        {
            NoSuchAlgorithmException nsae =
                    new NoSuchAlgorithmException("Jostle provider is not registered");
            nsae.initCause(e);
            throw nsae;
        }
    }

    private static String keyFactoryAlgorithm(OSSLKeyType type)
    {
        switch (type)
        {
            case ED25519:
            case Ed25519ctx:
            case Ed25519ph:
                return "ED25519";
            case ED448:
            case ED448ph:
                return "ED448";
            default:
                return type.getTypeName();
        }
    }

    private static byte[] encodePassword(char[] password)
    {
        if (password == null)
        {
            return null;
        }

        ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] encoded = new byte[buffer.remaining()];
        buffer.get(encoded);
        if (buffer.hasArray())
        {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return encoded;
    }

    private static char[] passwordFromProtection(
            KeyStore.ProtectionParameter protection)
        throws NoSuchAlgorithmException
    {
        if (protection == null)
        {
            return null;
        }
        if (protection instanceof KeyStore.PasswordProtection)
        {
            return ((KeyStore.PasswordProtection)protection).getPassword();
        }
        if (protection instanceof KeyStore.CallbackHandlerProtection)
        {
            CallbackHandler handler =
                    ((KeyStore.CallbackHandlerProtection)protection)
                            .getCallbackHandler();
            PasswordCallback callback = new PasswordCallback("Password: ", false);
            try
            {
                handler.handle(new Callback[] {callback});
                char[] password = callback.getPassword();
                if (password == null)
                {
                    throw new NoSuchAlgorithmException("No password provided");
                }
                return password;
            }
            catch (UnsupportedCallbackException e)
            {
                NoSuchAlgorithmException nsae =
                        new NoSuchAlgorithmException("Could not obtain password");
                nsae.initCause(e);
                throw nsae;
            }
            catch (IOException e)
            {
                NoSuchAlgorithmException nsae =
                        new NoSuchAlgorithmException("Could not obtain password");
                nsae.initCause(e);
                throw nsae;
            }
            finally
            {
                callback.clearPassword();
            }
        }
        throw new NoSuchAlgorithmException(
                "ProtectionParameter must be PasswordProtection or "
                        + "CallbackHandlerProtection");
    }

    private static int readAsn1Length(DataInputStream dataStream)
        throws IOException
    {
        int length = dataStream.readUnsignedByte();
        if ((length & 0x80) == 0)
        {
            return length;
        }

        int lengthBytes = length & 0x7f;
        if (lengthBytes == 0)
        {
            return -1;
        }
        if (lengthBytes > 4)
        {
            throw new IOException("ASN.1 length is too large");
        }

        length = 0;
        for (int i = 0; i < lengthBytes; i++)
        {
            length = (length << 8) | dataStream.readUnsignedByte();
        }
        return length;
    }

    private static byte[] encodeCertificateChain(Certificate[] chain)
        throws CertificateEncodingException
    {
        if (chain == null || chain.length == 0)
        {
            return null;
        }

        // Concatenated DER: each certificate encoding is a self-delimiting ASN.1
        // SEQUENCE, so the native side parses the run with d2i_X509 in a loop and
        // no length framing is needed.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Certificate certificate : chain)
        {
            if (certificate == null)
            {
                throw new CertificateEncodingException("certificate chain contains null");
            }
            byte[] encoded = certificate.getEncoded();
            if (encoded == null)
            {
                throw new CertificateEncodingException(
                        "certificate encoding is null");
            }
            out.write(encoded, 0, encoded.length);
        }
        return out.toByteArray();
    }

    private static Certificate[] decodeCertificateChain(byte[] encoded)
        throws CertificateException, IOException
    {
        if (encoded == null || encoded.length == 0)
        {
            return null;
        }

        CertificateFactory factory;
        try
        {
            factory = CertificateFactory.getInstance("X.509",
                    JostleProvider.PROVIDER_NAME);
        }
        catch (NoSuchProviderException e)
        {
            CertificateException ce =
                    new CertificateException("Jostle provider is not registered");
            ce.initCause(e);
            throw ce;
        }

        // The native side serialised the chain as concatenated DER; the X.509
        // factory reads the run back as an ordered collection.
        return factory.generateCertificates(new ByteArrayInputStream(encoded))
                .toArray(new Certificate[0]);
    }

    private static List<String> decodeAliases(byte[] encoded)
        throws IOException
    {
        if (encoded == null || encoded.length < 4)
        {
            return Collections.emptyList();
        }

        List<String> aliases = new ArrayList<String>();
        int offset = 0;
        int count = readInt(encoded, offset);
        offset += 4;
        if (count < 0)
        {
            throw new IOException("alias count is negative");
        }
        for (int i = 0; i < count; i++)
        {
            if (offset + 4 > encoded.length)
            {
                throw new IOException("alias length is truncated");
            }
            int length = readInt(encoded, offset);
            offset += 4;
            if (length < 0 || length > encoded.length - offset)
            {
                throw new IOException("alias value is truncated");
            }
            aliases.add(new String(encoded, offset, length, StandardCharsets.UTF_8));
            offset += length;
        }
        if (offset != encoded.length)
        {
            throw new IOException("aliases have trailing data");
        }
        return aliases;
    }

    private static int readInt(byte[] in, int offset)
    {
        return ((in[offset] & 0xff) << 24)
                | ((in[offset + 1] & 0xff) << 16)
                | ((in[offset + 2] & 0xff) << 8)
                | (in[offset + 3] & 0xff);
    }
}
