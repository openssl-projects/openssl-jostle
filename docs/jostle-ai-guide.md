# OpenSSL Jostle: worked examples

OpenSSL Jostle is a JCA/JCE provider that delegates to OpenSSL. Every example in this guide is a JUnit test
that runs against the built jar, so the code shown is code that works. See `SERVICES.md` for every
registered name.

<!-- Generated from jostle/src/test/examples; edit those and run ./gradlew :jostle:generateExamplesGuide -->

# Worked examples: JSL

Every JSL example below runs as a JUnit test against the built jar, from a package outside the jar, so it
uses only the exported API. Each example assumes this one-time setup, which registers the provider under
the name "JSL"; the examples then name it in every `getInstance` call.

```java
import org.openssl.jostle.jcajce.provider.JostleProvider;
import java.security.Security;

if (Security.getProvider("JSL") == null)
{
    Security.addProvider(new JostleProvider());
}
```

## MessageDigest

Message digests. Jostle registers OpenSSL's names (`SHA2-256`) and the JDK's (`SHA-256`) resolves to the
same service.

Imports used in this section:

```java
import org.openssl.jostle.util.encoders.Hex;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
```

### sha256OneShot

Hash a message with SHA-256, one shot. The expected value is the FIPS 180-2 vector for "abc".

```java
MessageDigest md = MessageDigest.getInstance("SHA-256", "JSL");
byte[] hash = md.digest("abc".getBytes(StandardCharsets.US_ASCII));
Assertions.assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Hex.toHexString(hash));
```

### sha3IncrementalUpdates

Hash a message fed in pieces; the result equals the one-shot hash. SHA3-256 of "abc" is the FIPS 202
vector.

```java
MessageDigest md = MessageDigest.getInstance("SHA3-256", "JSL");
md.update((byte) 'a');
md.update("bc".getBytes(StandardCharsets.US_ASCII), 0, 2);
byte[] hash = md.digest();
Assertions.assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        Hex.toHexString(hash));
```

### shakeDefaultOutputLengths

SHAKE is an extendable-output function. Through MessageDigest it produces its default length: 32 bytes
for SHAKE-128 and 64 for SHAKE-256, and the named variants fix the length in the name.

```java
byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
Assertions.assertEquals(32, MessageDigest.getInstance("SHAKE-128", "JSL").digest(msg).length);
Assertions.assertEquals(64, MessageDigest.getInstance("SHAKE-256", "JSL").digest(msg).length);
Assertions.assertEquals(32, MessageDigest.getInstance("SHAKE128-256", "JSL").digest(msg).length);
Assertions.assertEquals(64, MessageDigest.getInstance("SHAKE256-512", "JSL").digest(msg).length);
```

### everyOtherDigest

Every other digest JSL registers, driven the same way: the length the digest reports is the length it
produces, and a one-bit change in the input changes the output.

```java
String[] names = {"SHA1", "SHA2-224", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
        "SHA3-224", "SHA3-384", "SHA3-512", "MD5", "MD5-SHA1", "RIPEMD-160", "SM3", "BLAKE2B-512",
        "BLAKE2S-256"};
byte[] a = "abc".getBytes(StandardCharsets.US_ASCII);
byte[] b = "abd".getBytes(StandardCharsets.US_ASCII);
for (String name : names)
{
    MessageDigest md = MessageDigest.getInstance(name, "JSL");
    byte[] ha = md.digest(a);
    Assertions.assertEquals(md.getDigestLength(), ha.length, name);
    Assertions.assertFalse(MessageDigest.isEqual(ha, md.digest(b)), name);
}
```

## Mac

Message authentication codes. A receiver verifies a tag by computing it again and comparing with
`MessageDigest.isEqual`, which takes the same time whatever the bytes are.

Imports used in this section:

```java
import org.openssl.jostle.jcajce.spec.KMACParameterSpec;
import org.openssl.jostle.util.encoders.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
```

### hmacSha256

HMAC-SHA256 over a message. Key and message are RFC 4231 test case 1, so the tag is known.

```java
byte[] key = new byte[20];
Arrays.fill(key, (byte) 0x0b);
Mac mac = Mac.getInstance("HmacSHA256", "JSL");
mac.init(new SecretKeySpec(key, "HmacSHA256"));
byte[] tag = mac.doFinal("Hi There".getBytes(StandardCharsets.US_ASCII));
Assertions.assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        Hex.toHexString(tag));
```

### everyHmac

Every HMAC JSL registers: the receiver recomputes the tag and accepts it, and a changed message gives a
different tag.

```java
String[] names = {"HmacSHA1", "HmacSHA224", "HmacSHA384", "HmacSHA512", "HmacSHA512/224",
        "HmacSHA512/256", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512", "HmacMD5",
        "HmacMD5SHA1", "HmacRIPEMD160", "HmacSM3"};
byte[] key = "a 32-byte key for the HMAC demo!".getBytes(StandardCharsets.US_ASCII);
byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
for (String name : names)
{
    Mac sender = Mac.getInstance(name, "JSL");
    sender.init(new SecretKeySpec(key, name));
    byte[] tag = sender.doFinal(msg);
    Mac receiver = Mac.getInstance(name, "JSL");
    receiver.init(new SecretKeySpec(key, name));
    Assertions.assertTrue(MessageDigest.isEqual(tag, receiver.doFinal(msg)), name);
    Assertions.assertFalse(MessageDigest.isEqual(tag, receiver.doFinal("attack at dusk".getBytes(
            StandardCharsets.US_ASCII))), name);
}
```

### aesCmac

AES-CMAC takes an AES key of 16, 24 or 32 bytes and produces a 16-byte tag.

```java
SecretKeySpec key = new SecretKeySpec(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"), "AES");
Mac mac = Mac.getInstance("AESCMAC", "JSL");
mac.init(key);
byte[] tag = mac.doFinal(Hex.decode("6bc1bee22e409f96e93d7e117393172a"));
// NIST SP 800-38B example 2
Assertions.assertEquals("070a16b46b4d4144f79bdd9dd04a287c", Hex.toHexString(tag));
```

### aesGmac

AES-GMAC needs a nonce as well as the key. Use a fresh 12-byte nonce for every message under a key:
after one tag the instance refuses more input until it is initialised again.

```java
SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
byte[] nonce = Hex.decode("000102030405060708090a0b");
byte[] msg = "authenticated, not encrypted".getBytes(StandardCharsets.US_ASCII);
Mac sender = Mac.getInstance("AESGMAC", "JSL");
sender.init(key, new IvParameterSpec(nonce));
byte[] tag = sender.doFinal(msg);
Mac receiver = Mac.getInstance("AESGMAC", "JSL");
receiver.init(key, new IvParameterSpec(nonce));
Assertions.assertTrue(MessageDigest.isEqual(tag, receiver.doFinal(msg)));
Assertions.assertEquals(16, tag.length);
```

### poly1305

Poly1305 is a one-time authenticator: its 32-byte key must never be used for a second message.

```java
byte[] key = Hex.decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
Mac mac = Mac.getInstance("POLY1305", "JSL");
mac.init(new SecretKeySpec(key, "POLY1305"));
byte[] tag = mac.doFinal("Cryptographic Forum Research Group".getBytes(StandardCharsets.US_ASCII));
// RFC 8439 section 2.5.2
Assertions.assertEquals("a8061dc1305136c6c22b8baf0c0127a9", Hex.toHexString(tag));
```

### kmacWithCustomisation

KMAC takes an optional customisation string and output length through `KMACParameterSpec`; the same
key and message under a different customisation string give a different tag.

```java
SecretKeySpec key = new SecretKeySpec(new byte[32], "KMAC");
byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
for (String name : new String[]{"KMAC128", "KMAC256"})
{
    Mac a = Mac.getInstance(name, "JSL");
    a.init(key, new KMACParameterSpec(256, "app one".getBytes(StandardCharsets.US_ASCII)));
    byte[] tagA = a.doFinal(msg);
    Mac b = Mac.getInstance(name, "JSL");
    b.init(key, new KMACParameterSpec(256, "app two".getBytes(StandardCharsets.US_ASCII)));
    Assertions.assertEquals(32, tagA.length, name);
    Assertions.assertFalse(MessageDigest.isEqual(tagA, b.doFinal(msg)), name);
}
```

## SecretKeyFactory

Key derivation functions, all served as `SecretKeyFactory`: pass the inputs as a key spec to
`generateSecret` and read the derived bytes with `getEncoded()`. Password-based KDFs take the JDK's
`PBEKeySpec` or a Jostle spec; the others take a Jostle parameter spec.

Imports used in this section:

```java
import org.openssl.jostle.jcajce.spec.Argon2KeySpec;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.SSKDFParameterSpec;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.encoders.Hex;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
```

### pbkdf2WithHmacSha256

PBKDF2 with HMAC-SHA256. The key length in `PBEKeySpec` is in bits. The inputs are the published
PBKDF2-HMAC-SHA256 vector ("password", "salt", one iteration); use far more iterations in practice.

```java
SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "JSL");
PBEKeySpec spec = new PBEKeySpec("password".toCharArray(),
        "salt".getBytes(StandardCharsets.US_ASCII), 1, 256);
byte[] key = f.generateSecret(spec).getEncoded();
Assertions.assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        Hex.toHexString(key));
```

### everyPbkdf2

Every PBKDF2 variant: the same inputs derive the same key, and a different salt a different key. The
password is UTF-8 encoded, except under `PBKDF2WithASCII`, which keeps the low 8 bits of each char.

```java
String[] names = {"PBKDF2", "PBKDF2WithASCII", "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512-224",
        "PBKDF2WithHmacSHA512-256", "PBKDF2WithHmacSHA3-224", "PBKDF2WithHmacSHA3-256",
        "PBKDF2WithHmacSHA3-384", "PBKDF2WithHmacSHA3-512", "PBKDF2WithHmacMD5",
        "PBKDF2WithHmacMD5-SHA1", "PBKDF2WithHmacRIPEMD160", "PBKDF2WithHmacSM3",
        "PBKDF2WithHmacBLAKE2B-512", "PBKDF2WithHmacBLAKE2S-256"};
char[] password = "correct horse".toCharArray();
byte[] salt = "sixteen byte slt".getBytes(StandardCharsets.US_ASCII);
byte[] salt2 = "sixteen byte sl2".getBytes(StandardCharsets.US_ASCII);
for (String name : names)
{
    SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
    byte[] k1 = f.generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();
    byte[] k2 = f.generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();
    byte[] k3 = f.generateSecret(new PBEKeySpec(password, salt2, 1000, 256)).getEncoded();
    Assertions.assertEquals(32, k1.length, name);
    Assertions.assertArrayEquals(k1, k2, name);
    Assertions.assertFalse(Arrays.equals(k1, k3), name);
}
```

### hkdfSha256

HKDF extract-and-expand with `HKDFParameterSpec(ikm, salt, info, lengthInBytes)`. The inputs are
RFC 5869 test case 1.

```java
byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
byte[] salt = Hex.decode("000102030405060708090a0b0c");
byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
SecretKeyFactory f = SecretKeyFactory.getInstance("HKDF-SHA256", "JSL");
byte[] okm = f.generateSecret(new HKDFParameterSpec(ikm, salt, info, 42)).getEncoded();
Assertions.assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        + "34007208d5b887185865", Hex.toHexString(okm));
```

### hkdfAndSingleStepKdf

HKDF over the other digests, and the single-step (SP 800-56C) KDF, which takes a shared secret and
the other info. Output lengths are in bytes; different info gives a different key.

```java
byte[] secret = "a shared secret from a key agreement".getBytes(StandardCharsets.US_ASCII);
byte[] info = "context A".getBytes(StandardCharsets.US_ASCII);
byte[] info2 = "context B".getBytes(StandardCharsets.US_ASCII);
String[] hkdfNames = {"HKDF-SHA384", "HKDF-SHA512"};
for (String name : hkdfNames)
{
    SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
    byte[] k1 = f.generateSecret(new HKDFParameterSpec(secret, null, info, 48)).getEncoded();
    byte[] k2 = f.generateSecret(new HKDFParameterSpec(secret, null, info2, 48)).getEncoded();
    Assertions.assertEquals(48, k1.length, name);
    Assertions.assertFalse(Arrays.equals(k1, k2), name);
}
String[] ssNames = {"SSKDF-SHA1", "SSKDF-SHA224", "SSKDF-SHA256", "SSKDF-SHA384", "SSKDF-SHA512"};
for (String name : ssNames)
{
    SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
    byte[] k1 = f.generateSecret(new SSKDFParameterSpec(secret, info, 32)).getEncoded();
    byte[] k2 = f.generateSecret(new SSKDFParameterSpec(secret, info2, 32)).getEncoded();
    Assertions.assertEquals(32, k1.length, name);
    Assertions.assertFalse(Arrays.equals(k1, k2), name);
}
```

### kbkdfCounterMode

SP 800-108 key-based KDF in counter mode: a key-derivation key, a label and a context. The HMAC
variants take any key length; the CMAC variants take an AES key of the size in their name.

```java
byte[] label = "encryption".getBytes(StandardCharsets.US_ASCII);
byte[] context = "session 42".getBytes(StandardCharsets.US_ASCII);
String[] names = {"KBKDF-HMAC-SHA1", "KBKDF-HMAC-SHA224", "KBKDF-HMAC-SHA256", "KBKDF-HMAC-SHA384",
        "KBKDF-HMAC-SHA512", "KBKDF-CMAC-AES128", "KBKDF-CMAC-AES192", "KBKDF-CMAC-AES256"};
int[] keyBytes = {32, 32, 32, 32, 32, 16, 24, 32};
for (int i = 0; i < names.length; i++)
{
    SecretKeyFactory f = SecretKeyFactory.getInstance(names[i], "JSL");
    byte[] ki = new byte[keyBytes[i]];
    byte[] k1 = f.generateSecret(new KBKDFParameterSpec(ki, label, context, 32)).getEncoded();
    byte[] k2 = f.generateSecret(new KBKDFParameterSpec(ki, label, null, 32)).getEncoded();
    Assertions.assertEquals(32, k1.length, names[i]);
    Assertions.assertFalse(Arrays.equals(k1, k2), names[i]);
}
```

### sshKdf

The SSH key derivation of RFC 4253 section 7.2: the shared secret K, exchange hash H and session id
derive each of the six keys, chosen by the key type.

```java
byte[] k = Hex.decode("0000002100a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
byte[] h = "exchange hash, one per key exchange".getBytes(StandardCharsets.US_ASCII);
byte[] sessionId = h;
String[] names = {"SSHKDF-SHA1", "SSHKDF-SHA224", "SSHKDF-SHA256", "SSHKDF-SHA384", "SSHKDF-SHA512"};
for (String name : names)
{
    SecretKeyFactory f = SecretKeyFactory.getInstance(name, "JSL");
    byte[] enc = f.generateSecret(new SSHKDFParameterSpec(k, h, sessionId,
            SSHKDFParameterSpec.KeyType.ENCRYPTION_KEY_CLIENT_TO_SERVER, 32)).getEncoded();
    byte[] mac = f.generateSecret(new SSHKDFParameterSpec(k, h, sessionId,
            SSHKDFParameterSpec.KeyType.INTEGRITY_KEY_CLIENT_TO_SERVER, 32)).getEncoded();
    Assertions.assertEquals(32, enc.length, name);
    Assertions.assertFalse(Arrays.equals(enc, mac), name);
}
```

### scrypt

scrypt with `ScryptKeySpec(password, salt, N, r, p, keyLengthInBits)`. The inputs are the RFC 7914
vector ("password", "NaCl", N = 1024, r = 8, p = 16).

```java
SecretKeyFactory f = SecretKeyFactory.getInstance("SCRYPT", "JSL");
ScryptKeySpec spec = new ScryptKeySpec("password".toCharArray(),
        "NaCl".getBytes(StandardCharsets.US_ASCII), 1024, 8, 16, 512);
byte[] key = f.generateSecret(spec).getEncoded();
Assertions.assertEquals("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        + "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", Hex.toHexString(key));
```

### argon2id

Argon2id, version 1.3, with memory in kibibytes and the key length in bits. The same inputs derive
the same key; a different salt, a different key.

```java
SecretKeyFactory f = SecretKeyFactory.getInstance("ARGON2", "JSL");
char[] password = "correct horse".toCharArray();
byte[] salt = "sixteen byte slt".getBytes(StandardCharsets.US_ASCII);
byte[] k1 = f.generateSecret(new Argon2KeySpec(password, salt, 3, 4096, 1, 256)).getEncoded();
byte[] k2 = f.generateSecret(new Argon2KeySpec(password, salt, 3, 4096, 1, 256)).getEncoded();
byte[] k3 = f.generateSecret(new Argon2KeySpec(password, "sixteen byte sl2".getBytes(
        StandardCharsets.US_ASCII), 3, 4096, 1, 256)).getEncoded();
Assertions.assertEquals(32, k1.length);
Assertions.assertArrayEquals(k1, k2);
Assertions.assertFalse(Arrays.equals(k1, k3));
```

## SecureRandom

Random number generators backed by OpenSSL's DRBGs. The mechanism-named variants (`CTR-DRBG-AES256`,
`HASH-DRBG-SHA512`, `HMAC-DRBG-SHA256`, ...) pin the DRBG and its security strength.

Imports used in this section:

```java
import java.security.SecureRandom;
import java.util.Arrays;
```

### defaultGenerator

Draw random bytes from JSL's default generator. Two draws of the same length differ.

```java
SecureRandom random = SecureRandom.getInstance("DEFAULT", "JSL");
byte[] a = new byte[32];
byte[] b = new byte[32];
random.nextBytes(a);
random.nextBytes(b);
Assertions.assertFalse(Arrays.equals(a, b));
```

### everyDrbg

Pick a specific DRBG mechanism by name. Each seeds itself; `setSeed` adds caller material to it.

```java
String[] names = {"DRBG", "CTR-DRBG", "CTR-DRBG-AES128", "CTR-DRBG-AES192", "CTR-DRBG-AES256",
        "HASH-DRBG", "HASH-DRBG-SHA1", "HASH-DRBG-SHA224", "HASH-DRBG-SHA256", "HASH-DRBG-SHA384",
        "HASH-DRBG-SHA512", "HMAC-DRBG", "HMAC-DRBG-SHA1", "HMAC-DRBG-SHA224", "HMAC-DRBG-SHA256",
        "HMAC-DRBG-SHA384", "HMAC-DRBG-SHA512"};
for (String name : names)
{
    SecureRandom random = SecureRandom.getInstance(name, "JSL");
    random.setSeed(new byte[]{1, 2, 3});
    byte[] a = new byte[48];
    byte[] b = new byte[48];
    random.nextBytes(a);
    random.nextBytes(b);
    Assertions.assertFalse(Arrays.equals(a, b), name);
}
```

## Cipher

Ciphers: symmetric encryption, key wrapping, and public-key encryption and key transport. Generate a fresh
key and a fresh IV or nonce for every message; the fixed IVs below only keep the examples short.

Imports used in this section:

```java
import org.openssl.jostle.jcajce.spec.IESKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;
import org.openssl.jostle.util.encoders.Hex;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
```

### aesGcmEncryptAndDecrypt

AES-GCM with additional authenticated data. The ciphertext carries the 16-byte tag at its end, and any
change to it, or to the AAD, fails decryption with `AEADBadTagException`.

```java
KeyGenerator kg = KeyGenerator.getInstance("AES", "JSL");
kg.init(256);
SecretKey key = kg.generateKey();
byte[] nonce = Hex.decode("cafebabefacedbaddecaf888");
byte[] aad = "header".getBytes(StandardCharsets.US_ASCII);
byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);

Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
enc.updateAAD(aad);
byte[] ct = enc.doFinal(msg);

Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
dec.updateAAD(aad);
Assertions.assertArrayEquals(msg, dec.doFinal(ct));

ct[0] ^= 1;
dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
dec.updateAAD(aad);
Assertions.assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct));
```

### ccmEncryptAndDecrypt

AES-CCM is its own transformation. With a plain `IvParameterSpec` its tag is 64 bits (GCM's is 128);
pass a `GCMParameterSpec` to choose the tag length. The same holds for ARIA and SM4.

```java
String[] names = {"AES/CCM/NoPadding", "ARIA/CCM/NoPadding", "SM4/CCM/NoPadding"};
String[] keyAlgs = {"AES", "ARIA", "SM4"};
byte[] nonce = Hex.decode("00112233445566778899aabb");
byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
for (int i = 0; i < names.length; i++)
{
    SecretKeySpec key = new SecretKeySpec(new byte[16], keyAlgs[i]);
    Cipher enc = Cipher.getInstance(names[i], "JSL");
    enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
    byte[] ct = enc.doFinal(msg);
    Assertions.assertEquals(msg.length + 8, ct.length, names[i]);
    Cipher dec = Cipher.getInstance(names[i], "JSL");
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(64, nonce));
    Assertions.assertArrayEquals(msg, dec.doFinal(ct), names[i]);
}
```

### cbcOverEveryBlockCipher

CBC with PKCS#5 padding over each block cipher, with a key of any size the cipher supports. The IV is
one block: 16 bytes, or 8 for DESede.

```java
String[] names = {"AES", "ARIA", "CAMELLIA", "SM4", "DESEDE"};
int[] keyBytes = {32, 32, 32, 16, 24};
byte[] msg = "twenty-five bytes of text".getBytes(StandardCharsets.US_ASCII);
for (int i = 0; i < names.length; i++)
{
    Cipher enc = Cipher.getInstance(names[i] + "/CBC/PKCS5Padding", "JSL");
    SecretKeySpec key = new SecretKeySpec(new byte[keyBytes[i]], names[i]);
    IvParameterSpec iv = new IvParameterSpec(new byte[enc.getBlockSize()]);
    enc.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] ct = enc.doFinal(msg);
    Cipher dec = Cipher.getInstance(names[i] + "/CBC/PKCS5Padding", "JSL");
    dec.init(Cipher.DECRYPT_MODE, key, iv);
    Assertions.assertArrayEquals(msg, dec.doFinal(ct), names[i]);
}
```

### sizePinnedEcbNames

The names with a size in them (`AES128`, `ARIA256`, ...) are the ECB entries of the NIST, KISA and
NTT object identifiers: ECB only, and only with a key of that size. For any other mode use the bare
name. ECB leaks patterns in the plaintext; do not use it for data.

```java
String[] names = {"AES128", "AES192", "AES256", "ARIA128", "ARIA192", "ARIA256", "CAMELLIA128",
        "CAMELLIA192", "CAMELLIA256"};
int[] keyBytes = {16, 24, 32, 16, 24, 32, 16, 24, 32};
byte[] block = "sixteen byte blk".getBytes(StandardCharsets.US_ASCII);
for (int i = 0; i < names.length; i++)
{
    SecretKeySpec key = new SecretKeySpec(new byte[keyBytes[i]], names[i]);
    Cipher enc = Cipher.getInstance(names[i] + "/ECB/NoPadding", "JSL");
    enc.init(Cipher.ENCRYPT_MODE, key);
    byte[] ct = enc.doFinal(block);
    Cipher dec = Cipher.getInstance(names[i] + "/ECB/NoPadding", "JSL");
    dec.init(Cipher.DECRYPT_MODE, key);
    Assertions.assertArrayEquals(block, dec.doFinal(ct), names[i]);
}
```

### aesCiphertextStealing

Ciphertext stealing: CBC without padding for any input of at least one block, the ciphertext the same
length as the plaintext. `AES/CBC/CS3Padding` and `AES/CTS/NoPadding` are the same construction.

```java
SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
IvParameterSpec iv = new IvParameterSpec(new byte[16]);
byte[] msg = "twenty-five bytes of text".getBytes(StandardCharsets.US_ASCII);
for (String name : new String[]{"AES/CBC/CS3Padding", "AES/CTS/NoPadding"})
{
    Cipher enc = Cipher.getInstance(name, "JSL");
    enc.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] ct = enc.doFinal(msg);
    Assertions.assertEquals(msg.length, ct.length, name);
    Cipher dec = Cipher.getInstance(name, "JSL");
    dec.init(Cipher.DECRYPT_MODE, key, iv);
    Assertions.assertArrayEquals(msg, dec.doFinal(ct), name);
}
```

### aesXts

AES-XTS for storage encryption: a double-length key (two different AES keys) and a 16-byte tweak,
usually the sector number. Each data unit is at least 16 bytes.

```java
byte[] keyBytes = new byte[64];
for (int i = 0; i < keyBytes.length; i++)
{
    keyBytes[i] = (byte) i;
}
SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
IvParameterSpec tweak = new IvParameterSpec(Hex.decode("07000000000000000000000000000000"));
byte[] sector = "a sector of forty bytes of disk content.".getBytes(StandardCharsets.US_ASCII);
Cipher enc = Cipher.getInstance("AES/XTS/NoPadding", "JSL");
enc.init(Cipher.ENCRYPT_MODE, key, tweak);
byte[] ct = enc.doFinal(sector);
Cipher dec = Cipher.getInstance("AES/XTS/NoPadding", "JSL");
dec.init(Cipher.DECRYPT_MODE, key, tweak);
Assertions.assertArrayEquals(sector, dec.doFinal(ct));
```

### chaCha20

ChaCha20-Poly1305 (authenticated) and plain ChaCha20 (a stream cipher, no integrity), both with a
32-byte key and a 12-byte nonce given as an `IvParameterSpec`.

```java
SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
IvParameterSpec nonce = new IvParameterSpec(Hex.decode("000000000000004a00000000"));
byte[] msg = "attack at dawn".getBytes(StandardCharsets.US_ASCII);
for (String name : new String[]{"ChaCha20-Poly1305", "ChaCha20"})
{
    Cipher enc = Cipher.getInstance(name, "JSL");
    enc.init(Cipher.ENCRYPT_MODE, key, nonce);
    byte[] ct = enc.doFinal(msg);
    Cipher dec = Cipher.getInstance(name, "JSL");
    dec.init(Cipher.DECRYPT_MODE, key, nonce);
    Assertions.assertArrayEquals(msg, dec.doFinal(ct), name);
}
```

### aesKeyWrap

AES key wrap (RFC 3394) of a 16-byte key under a 16-byte key-encryption key; the result is the RFC's
own test vector. A tampered blob fails `unwrap` with `InvalidKeyException`.

```java
SecretKeySpec kek = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
Cipher wrapper = Cipher.getInstance("AESWRAP", "JSL");
wrapper.init(Cipher.WRAP_MODE, kek);
byte[] wrapped = wrapper.wrap(cek);
Assertions.assertEquals("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", Hex.toHexString(wrapped));

Cipher unwrapper = Cipher.getInstance("AESWRAP", "JSL");
unwrapper.init(Cipher.UNWRAP_MODE, kek);
Key back = unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded());
```

### otherKeyWraps

The other wrap modes: `AESWRAPPAD` (RFC 5649) wraps a key of any length, `AESWRAPINV` is RFC 3394
with the inverse cipher, and the RFC 3211 wraps take an IV and add random padding, so each wrap of the
same key differs.

```java
String[] names = {"AESWRAPPAD", "AESWRAPINV", "AESRFC3211WRAP", "CAMELLIARFC3211WRAP",
        "DESEDERFC3211WRAP"};
int[] ivBytes = {0, 0, 16, 16, 8};
SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
for (int i = 0; i < names.length; i++)
{
    SecretKeySpec kek = new SecretKeySpec(new byte[24], names[i]);
    Cipher w = Cipher.getInstance(names[i], "JSL");
    Cipher u = Cipher.getInstance(names[i], "JSL");
    if (ivBytes[i] == 0)
    {
        w.init(Cipher.WRAP_MODE, kek);
        u.init(Cipher.UNWRAP_MODE, kek);
    }
    else
    {
        w.init(Cipher.WRAP_MODE, kek, new IvParameterSpec(new byte[ivBytes[i]]));
        u.init(Cipher.UNWRAP_MODE, kek, new IvParameterSpec(new byte[ivBytes[i]]));
    }
    Key back = u.unwrap(w.wrap(cek), "AES", Cipher.SECRET_KEY);
    Assertions.assertArrayEquals(cek.getEncoded(), back.getEncoded(), names[i]);
}
```

### rsaOaep

RSA-OAEP. JSL's bare `RSA` cipher is OAEP with SHA-256 and MGF1-SHA-256, not PKCS#1 v1.5 and not
SHA-1, so give both sides an explicit `OAEPParameterSpec` when the peer is another provider.

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();
OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
        PSource.PSpecified.DEFAULT);
byte[] msg = "a 32-byte session key goes here!".getBytes(StandardCharsets.US_ASCII);

Cipher enc = Cipher.getInstance("RSA", "JSL");
enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
byte[] ct = enc.doFinal(msg);
Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", "JSL");
dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
Assertions.assertArrayEquals(msg, dec.doFinal(ct));
```

### rsaPkcs1

RSA with PKCS#1 v1.5 padding, for interoperating with systems that still require it. Prefer OAEP for
anything new.

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();
byte[] msg = "legacy key transport".getBytes(StandardCharsets.US_ASCII);
Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "JSL");
enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
byte[] ct = enc.doFinal(msg);
Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "JSL");
dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
Assertions.assertArrayEquals(msg, dec.doFinal(ct));
```

### kemKeyTransport

Key transport through a KEM: the `ML-KEM` and `RSA-KTS-KEM-KWS` ciphers encapsulate a secret to the
recipient's public key, derive a key-encryption key (KDF3 with SHA-256 by default) and AES-wrap the
key. `KTSParameterSpec` names the wrap and its key size, and both sides must use the same one.

```java
String[] ciphers = {"ML-KEM", "RSA-KTS-KEM-KWS"};
String[] keyPairs = {"ML-KEM-768", "RSA"};
SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
KTSParameterSpec kts = new KTSParameterSpec.Builder("AESWRAP", 256).build();
for (int i = 0; i < ciphers.length; i++)
{
    KeyPair kp = KeyPairGenerator.getInstance(keyPairs[i], "JSL").generateKeyPair();
    Cipher w = Cipher.getInstance(ciphers[i], "JSL");
    w.init(Cipher.WRAP_MODE, kp.getPublic(), kts);
    byte[] wrapped = w.wrap(cek);
    Cipher u = Cipher.getInstance(ciphers[i], "JSL");
    u.init(Cipher.UNWRAP_MODE, kp.getPrivate(), kts);
    Assertions.assertArrayEquals(cek.getEncoded(), u.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(),
            ciphers[i]);
}
```

### etsiKemWrap

The ETSI EC key-encapsulation wrap (ETSI TS 102 941): wrap a key to an EC public key. The recipient
info in `IESKEMParameterSpec` is bound into the derivation, so both sides must pass the same bytes.

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair recipient = kpg.generateKeyPair();
byte[] recipientInfo = "recipient id".getBytes(StandardCharsets.US_ASCII);
SecretKeySpec cek = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");

Cipher w = Cipher.getInstance("ETSIKEMwithSHA256", "JSL");
w.init(Cipher.WRAP_MODE, recipient.getPublic(), new IESKEMParameterSpec(recipientInfo));
byte[] wrapped = w.wrap(cek);
Cipher u = Cipher.getInstance("ETSIKEMwithSHA256", "JSL");
u.init(Cipher.UNWRAP_MODE, recipient.getPrivate(), new IESKEMParameterSpec(recipientInfo));
Key back = u.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
Assertions.assertTrue(Arrays.equals(cek.getEncoded(), back.getEncoded()));
```

## AlgorithmParameters

Algorithm parameters: the ASN.1 encoding of a cipher's IV or nonce, a curve, or a signature's settings,
as they travel in CMS, PKCS#8 or X.509. Encode with `getEncoded()`, decode with `init(byte[])`, and read
the spec back with `getParameterSpec`.

Imports used in this section:

```java
import org.openssl.jostle.util.encoders.Hex;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
```

### gcmParametersFromACipher

A cipher reports its parameters after `init`; encode them to send with the ciphertext, and rebuild them
on the other side to initialise the decrypting cipher.

```java
SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, Hex.decode("cafebabefacedbaddecaf888")));
byte[] encoded = enc.getParameters().getEncoded();

AlgorithmParameters params = AlgorithmParameters.getInstance("GCM", "JSL");
params.init(encoded);
GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
Assertions.assertEquals(128, spec.getTLen());
Assertions.assertEquals("cafebabefacedbaddecaf888", Hex.toHexString(spec.getIV()));
```

### ivParametersRoundTrip

The IV parameters of the block ciphers, and the nonce parameters of CCM and ChaCha20-Poly1305: build
from a spec, encode, decode into a fresh instance, and read the same IV back.

```java
String[] names = {"AES", "ARIA", "CAMELLIA", "SM4", "DESEDE", "CCM", "CHACHA20-POLY1305"};
int[] ivBytes = {16, 16, 16, 16, 8, 12, 12};
for (int i = 0; i < names.length; i++)
{
    byte[] iv = new byte[ivBytes[i]];
    iv[0] = 42;
    AlgorithmParameters params = AlgorithmParameters.getInstance(names[i], "JSL");
    params.init(new IvParameterSpec(iv));
    AlgorithmParameters decoded = AlgorithmParameters.getInstance(names[i], "JSL");
    decoded.init(params.getEncoded());
    Assertions.assertArrayEquals(iv, decoded.getParameterSpec(IvParameterSpec.class).getIV(), names[i]);
}
```

### ecNamedCurve

EC parameters from a curve name: `getParameterSpec(ECParameterSpec.class)` gives the full curve
definition, and the encoding is the named-curve OID.

```java
AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "JSL");
params.init(new ECGenParameterSpec("secp256r1"));
ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
Assertions.assertEquals(256, curve.getOrder().bitLength());
// 06 08 = OID 1.2.840.10045.3.1.7
Assertions.assertEquals("06082a8648ce3d030107", Hex.toHexString(params.getEncoded()));
```

### rsaPssParameters

RSASSA-PSS parameters, the form a PSS signature's AlgorithmIdentifier carries: digest, mask generation,
salt length and trailer field.

```java
PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
params.init(pss);
AlgorithmParameters decoded = AlgorithmParameters.getInstance("RSASSA-PSS", "JSL");
decoded.init(params.getEncoded());
PSSParameterSpec back = decoded.getParameterSpec(PSSParameterSpec.class);
Assertions.assertEquals(32, back.getSaltLength());
Assertions.assertEquals("SHA-256", back.getDigestAlgorithm());
```

## AlgorithmParameterGenerator

Parameter generators for finite-field Diffie-Hellman and DSA. The size is the caller's choice: JSL accepts
any size OpenSSL will generate, including sizes too small to be safe. Where a named group will do, prefer
it; generating DH parameters is slow.

Imports used in this section:

```java
import javax.crypto.spec.DHParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.spec.DSAParameterSpec;
```

### dsaDomainParameters

Generate DSA domain parameters (p, q, g), and read them from the generated `AlgorithmParameters` in
the encoding a certificate carries.

```java
AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA", "JSL");
gen.init(2048);
AlgorithmParameters params = gen.generateParameters();
DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);
Assertions.assertEquals(2048, spec.getP().bitLength());
Assertions.assertEquals(256, spec.getQ().bitLength());

AlgorithmParameters decoded = AlgorithmParameters.getInstance("DSA", "JSL");
decoded.init(params.getEncoded());
Assertions.assertEquals(spec.getG(), decoded.getParameterSpec(DSAParameterSpec.class).getG());
```

### dhParameters

Generate Diffie-Hellman parameters: a safe prime p and generator g. 1024 bits keeps the example quick;
use 2048 or more.

```java
AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH", "JSL");
gen.init(1024);
AlgorithmParameters params = gen.generateParameters();
DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
Assertions.assertEquals(1024, spec.getP().bitLength());

AlgorithmParameters decoded = AlgorithmParameters.getInstance("DH", "JSL");
decoded.init(params.getEncoded());
Assertions.assertEquals(spec.getP(), decoded.getParameterSpec(DHParameterSpec.class).getP());
```
