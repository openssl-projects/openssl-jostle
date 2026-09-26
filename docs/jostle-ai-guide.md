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
