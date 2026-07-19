---
title: OpenSSL Jostle — Guide for AI Coding Assistants
audience: An AI coding assistant helping a developer USE the OpenSSL Jostle JCE/JCA provider as a dependency.
scope: Provider setup and deployment (incl. FIPS), defaults that deviate from the JDK, exception contracts, interop traps, and verified usage snippets.
not_covered: Building or contributing to Jostle itself (see CONTRIBUTING.md and CLAUDE.md in the Jostle repo).
authoritative_sources:
  - "SERVICES.md — the complete, generated list of every algorithm each provider registers."
  - "README.md — install, provider configuration, FIPS behaviour, loader properties."
guide_targets: Jostle 1.0 (JSL / JSLFIPS). Algorithm names below are illustrative; SERVICES.md is authoritative.
---

# OpenSSL Jostle — Guide for AI Coding Assistants

You are helping a developer write Java that uses **OpenSSL Jostle**, a JCA/JCE
`Provider` that delegates cryptography to the native OpenSSL library. This file
is written for you (an AI assistant), not for the end user. Read it before
generating any Jostle code, then generate standard JCE code — Jostle is used
through `javax.crypto.*` / `java.security.*`, never through a bespoke API.

**When in doubt about whether an algorithm/transformation exists, consult
`SERVICES.md` — it is the generated, authoritative inventory. Do not invent
transformation strings.**

## Wire this guide into the assistant

This file is portable Markdown. To make an assistant use it, reference it from
whatever instruction file that assistant loads (all of these just need to point
here — keep the content in this one file):

1. **Claude / Claude Code** → add a line to `CLAUDE.md`: "For OpenSSL Jostle usage, read `docs/jostle-ai-guide.md`."
2. **GitHub Copilot** → same line in `.github/copilot-instructions.md`.
3. **OpenAI Codex (and other `AGENTS.md`-aware tools)** → same line in `AGENTS.md`.
4. **Cursor** → add `.cursor/rules/jostle.mdc` pointing here.
5. **Anything else** → paste this file into the assistant's project/custom instructions, or keep it in the repo and tell the assistant to read it.

All mainstream assistants parse Markdown identically; there is nothing
vendor-specific in the content itself.

## What Jostle is, in one screen

1. Two providers ship in the same jar and can coexist in one JVM:
   1. **`JSL`** (`JostleProvider`) — the general provider, backed by mainline OpenSSL 3.x. Full algorithm set.
   2. **`JSLFIPS`** (`JostleFIPSProvider`) — backed by an externally supplied OpenSSL **FIPS** module. Registers only the subset the module serves as approved, and behaves differently in several documented ways (see FIPS sections).
2. Runs on Java 8 → Java 25 (multi-release jar). On Java 25 it uses the FFI backend; on older JDKs, JNI. Invisible to your code.
3. Choose `JSL` for general use; use `JSLFIPS` only when the deployment mandates the FIPS-validated module.

## Setup & deployment

### Register the `JSL` provider

Programmatically:

```java
import org.openssl.jostle.jcajce.provider.JostleProvider;
import java.security.Security;

Security.addProvider(new JostleProvider());   // registers a provider named "JSL"
```

Or statically in the `java.security` file (fully-qualified class names):

```
security.provider.N=org.openssl.jostle.jcajce.provider.JostleProvider
# FIPS:
security.provider.M=org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider
```

Then request algorithms by the provider name:

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
```

### Enable native access (Java 9+)

Add `--enable-native-access=org.openssl.jostle.prov` on the module path (or
`=ALL-UNNAMED` on the classpath) to silence the restricted-native-access warning.
The module name is `org.openssl.jostle.prov`.

### Deployment system properties (`-D…`)

1. `org.openssl.jostle.loader.install_dir=<dir>` — extract native libs to `<dir>` instead of the JVM temp dir. **Essential when the temp filesystem is mounted `noexec`** (common enterprise hardening) — otherwise the native load fails.
2. `org.openssl.jostle.loader.single_install=true` — use a fixed install location (pair with `install_dir`); avoids duplicate extraction when many JVMs run.
3. `org.openssl.jostle.loader.interface=auto|jni|ffi|none` — force the backend (default `auto`: FFI on Java 25, JNI otherwise).

### Verify the load

Confirm the provider loaded its native backend and see the OpenSSL version and
full service list:

```
java --module-path openssl-jostle-<version>.jar \
  --enable-native-access=org.openssl.jostle.prov \
  --module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo --services
```

Reports the provider, resolved interface (JNI/FFI), extracted native libs,
OpenSSL version, and (with `--services`) every registered algorithm grouped by
type. Use it to confirm a deployment picked up the native libraries.

### Set up the FIPS provider (`JSLFIPS`)

`JSLFIPS` backs its services with an **externally supplied** OpenSSL FIPS module
(e.g. the FIPS-validated OpenSSL 3.1.2 `fips.so` / `fips.dylib` / `fips.dll`).
The module is loaded by libcrypto itself — its integrity MAC is verified and its
self-tests run before any service is available; the JVM never `System.load`s it.
**`JSLFIPS` registers no services until configured.**

Configuration is a comma-separated `key=value` list. Values may be quoted (`"`,
`'`, or backtick) and resolved via schemes `file:` (path), `env:` (environment
variable), `prop:` (java.security/system property), or `str:` (literal). Keys:

1. `fips_module` — **REQUIRED**. Path to the FIPS module. Its parent directory becomes the module search path; the OpenSSL provider name is the file name minus its extension.
2. `fips_config` — OPTIONAL. Path to the fipsinstall-generated configuration carrying the module MAC. Defaults to `fipsmodule.cnf` in the module's directory.

Three ways to configure:

```java
// 1. Constructor with an inline config string:
Security.addProvider(new JostleFIPSProvider(
        "fips_module='/opt/openssl-fips/lib/ossl-modules/fips.so'"));

// 2. No-arg + configure() — e.g. resolve the path from an env var:
Provider p = new JostleFIPSProvider().configure("fips_module=env:MY_FIPS_MODULE");
Security.addProvider(p);

// 3. Static registration + the config property. In java.security:
//      security.provider.N=org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider
//    and at launch:
//      -Dorg.openssl.jostle.fips.config=fips_module=file:/opt/openssl-fips/lib/ossl-modules/fips.so
```

The no-arg constructor consults `org.openssl.jostle.fips.config` (java.security
property, then a thread-local override, then the system property); with no
configuration it stays unconfigured and registers nothing.

**Initialisation is one-shot per JVM.** Constructing another `JSLFIPS` with the
*identical* configuration is a no-op; a *different* configuration throws
`IllegalStateException`. You cannot change the FIPS module after the first
initialisation.

Once configured, use it by the provider name `"JSLFIPS"`, exactly like `"JSL"`:

```java
Signature s = Signature.getInstance("SHA256withECDSA", "JSLFIPS");
```

(`TEST_FIPS_LIB` mentioned in the repo is only for running Jostle's own
test-suite — callers do not need it.)

## The traps — read these before generating code

These are the things a JCE-experienced assistant gets *wrong* by assuming Jostle
behaves like SunJCE. Each is a real, deliberate Jostle behaviour.

### 1. Randomised defaults differ from the JDK — pass explicit params for interop

1. `Cipher.getInstance("RSA", "JSL")` is **RSA-OAEP with SHA-256 / MGF1-SHA-256** (not PKCS#1 v1.5, and not SHA-1). PKCS#1 v1.5 *encryption* is a separate transformation: `"RSA/ECB/PKCS1Padding"`.
2. `Signature.getInstance("RSASSA-PSS", "JSL")` defaults to **SHA-256 / MGF1-SHA-256**, not SHA-1.

Consequence for you:

1. **Do NOT assume default-vs-default parity across providers.** If the code must interoperate with SunJCE, BouncyCastle, or a peer system, construct explicit `OAEPParameterSpec` / `PSSParameterSpec` objects and pass them to both sides.
2. **Do NOT assert that two signatures/ciphertexts of the same input are equal** for PSS, OAEP, or PKCS#1 v1.5 *encryption* — they are randomised and differ every call. (PKCS#1 v1.5 *signing* is deterministic and does repeat.)

### 2. Post-quantum algorithms need a strong RNG

ML-KEM-768/1024, ML-DSA-65/87, and SLH-DSA-*-192/256 require RNG strength above
the JDK's default 128-bit DRBG.

1. Prefer to pass **no** `SecureRandom` — Jostle selects a strength-appropriate DRBG automatically.
2. If you must pass one, use an adequate DRBG (e.g. `SecureRandom.getInstance("DRBG", ...)` at ≥192/256 bits) or one of Jostle's own, e.g. `SecureRandom.getInstance("CTR-DRBG-AES256", "JSL")`.
3. A `SecureRandom` reporting a non-zero strength below the requirement is rejected with `InvalidAlgorithmParameterException`; strength 0 ("unknown", e.g. plain `new SecureRandom()` on Java 8) is accepted and the native layer is the safety net.

### 3. Exception contracts — catch the right type

1. `Cipher.unwrap(...)` failures surface as **`InvalidKeyException`**, never `BadPaddingException` — a deliberate Bleichenbacher-channel defence.
2. `Cipher.doFinal(...)` decrypt padding/tag failures surface as **`BadPaddingException`** (GCM: its subclass `AEADBadTagException`); size mismatches as `IllegalBlockSizeException`; short output buffers as `ShortBufferException`.
3. Illegal state-machine transitions (e.g. `update` before `init`, `setParameter` mid-update) throw **`IllegalStateException`**, not NPE. Call the SPI in order (init → update* → doFinal/sign/verify) rather than null-guarding.

### 4. Keys are bound to the provider that created them (JSL vs JSLFIPS)

1. **Public keys** carry no secret material and may be used with either provider freely.
2. **Private keys** are isolated: a `Signature`/`Cipher`/`KeyAgreement` of one provider **rejects** a private key created by the other with `InvalidKeyException`.
3. To move a private key between `JSL` and `JSLFIPS`, encode it (`key.getEncoded()`) and decode it through the **target** provider's `KeyFactory`. Do the crossing explicitly.
4. `SecretKey`s (raw bytes, no native residency) cross freely.

### 5. AEAD parameter specs and default tag lengths

1. GCM accepts both `GCMParameterSpec` (tag bits + nonce) and plain `IvParameterSpec`. When only an IV is given, the default tag length is **128 bits**.
2. CCM is a **dedicated transformation** — use `"AES/CCM/NoPadding"` (likewise `"ARIA/CCM/NoPadding"`, `"SM4/CCM/NoPadding"`), not `setMode("CCM")`. Its default tag on the `IvParameterSpec` path is **64 bits** (matches BouncyCastle, differs from GCM). Pass a `GCMParameterSpec` for a specific CCM tag length.
3. GCM/OCB enforce a nonce-reuse guard: after one successful encryption the instance rejects further data until re-init. Re-init with a fresh nonce per message.

## FIPS (`JSLFIPS`) behavioural differences

Beyond serving a smaller algorithm set, `JSLFIPS` differs from `JSL` in ways that
change *caller* code. Jostle fails loud (typed exception) rather than running
degraded:

1. **RSA PKCS#1 v1.5 encryption/decryption is unavailable.** `"RSA/ECB/PKCS1Padding"` is not registered, and PKCS#1 v1.5 *decrypt* is refused at the native layer too (the 3.1.2 module lacks the implicit-rejection mitigation). Use `"RSA/ECB/OAEPPadding"` for key transport. PKCS#1 v1.5 *signatures* remain available.
2. **DH parameter generation is refused** (`ProviderException`): the module substitutes RFC 7919 named-group constants instead of a real safe-prime search. Use named-group DH key generation instead.
3. **DH key agreement requires the subgroup order q.** Keys built from PKCS#3 component specs (p, g, x only) fail `KeyAgreement.init` with `InvalidKeyException`. Use named-group-derived keys.
4. **A caller-supplied `SecureRandom` is ignored** by every operation that runs inside the FIPS module (keygen, ECDSA nonces, PSS salts, OAEP seeds) — the module uses its own approved DRBG. Passing one is harmless but has no effect. (The AES `KeyGenerator` is the one nuance — see README.md "Entropy".)
5. **Absent families** (use `JSL` if you need them): MD5, SM3, RIPEMD, BLAKE2, ChaCha20, Camellia, ARIA, SM4, DESede, Poly1305, scrypt, Ed25519/Ed448, and all post-quantum (ML-KEM, ML-DSA, SLH-DSA); plus X25519/X448 key agreement.

## Algorithm inventory

The complete, current list of registered names and OID aliases for both
providers is in **`SERVICES.md`** (generated from the provider itself — it never
drifts from what the code registers). Consult it rather than guessing. As
orientation, `JSL` registers, among others:

1. **Cipher**: `AES` (+ `AES/GCM/NoPadding`, `AES/CCM/NoPadding`), `ARIA`, `CAMELLIA`, `SM4`, `CHACHA20`, `CHACHA20-POLY1305`, `DESEDE`, `RSA` (= OAEP), `RSA/ECB/PKCS1Padding`, `ML-KEM`.
2. **Signature**: `RSASSA-PSS`, `SHA256WithRSA`, `SHA256WithRSAandMGF1`, `SHA256WithECDSA`, `Ed25519`/`Ed448`, `ML-DSA-44/65/87`, `SLH-DSA-*`.
3. **KeyAgreement**: `ECDH`, `X25519`, `X448`, `DH` (+ `*withSHAnKDF` variants).
4. **KeyPairGenerator / KeyFactory**: `RSA`, `EC`, `DSA`, `DH`, `Ed25519`/`Ed448`, `X25519`/`X448`, `ML-KEM-*`, `ML-DSA-*`, `SLH-DSA-*`.
5. **MessageDigest**: `SHA2-256` (alias `SHA-256`), `SHA3-256`, `SHAKE-128/256`, `BLAKE2*`, `SM3`, etc.
6. **Mac**: `HmacSHA256`, `AESCMAC`, `POLY1305`, etc.
7. **SecretKeyFactory (KDFs)**: `PBKDF2`, `HKDF-SHA256/384/512`, `SCRYPT`.
8. **KeyStore**: `PKCS12` (+ variants). **SecureRandom**: `DRBG`, `CTR-DRBG`, `HASH-DRBG`, `HMAC-DRBG` families.

Algorithm names are case-insensitive per JCA, and JDK-standard aliases (e.g.
`SHA-256`) resolve alongside Jostle's OpenSSL-style names (`SHA2-256`).
Mode/padding variants (e.g. `AES/GCM/NoPadding`,
`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`) resolve through the standard JCE
transformation-lookup fallback even when only the bare name appears in
`SERVICES.md`.

## Canonical snippets

Standard JCE — the only Jostle-specific parts are the provider name `"JSL"` and
the traps above. Randomness, keys, and IVs must be generated fresh (never
hardcoded).

### AES-GCM

```java
KeyGenerator kg = KeyGenerator.getInstance("AES", "JSL");
kg.init(256);
SecretKey key = kg.generateKey();

byte[] nonce = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(nonce);

Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
enc.updateAAD(aad);                       // optional
byte[] ct = enc.doFinal(plaintext);       // ciphertext || 16-byte tag

Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", "JSL");
dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
dec.updateAAD(aad);
byte[] pt = dec.doFinal(ct);              // throws AEADBadTagException on tamper
```

### RSA-OAEP (key transport)

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "JSL");
kpg.initialize(3072);
KeyPair kp = kpg.generateKeyPair();

// Explicit params so both ends agree (do NOT rely on default parity):
OAEPParameterSpec oaep = new OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding", "JSL");
enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
byte[] ct = enc.doFinal(sessionKeyBytes);

Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", "JSL");
dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
byte[] pt = dec.doFinal(ct);              // BadPaddingException on failure
```

### RSASSA-PSS

```java
Signature s = Signature.getInstance("RSASSA-PSS", "JSL");
s.setParameter(new PSSParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)); // explicit for interop
s.initSign(privateKey);
s.update(message);
byte[] sig = s.sign();                     // randomised: differs each call

s.initVerify(publicKey);
s.update(message);
boolean ok = s.verify(sig);
```

### ECDSA

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair kp = kpg.generateKeyPair();

Signature s = Signature.getInstance("SHA256withECDSA", "JSL");
s.initSign(kp.getPrivate()); s.update(message); byte[] sig = s.sign();
s.initVerify(kp.getPublic()); s.update(message); boolean ok = s.verify(sig);
```

### X25519 key agreement (JSL only — not in JSLFIPS)

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "JSL");
KeyPair alice = kpg.generateKeyPair();
KeyPair bob   = kpg.generateKeyPair();

KeyAgreement ka = KeyAgreement.getInstance("X25519", "JSL");
ka.init(alice.getPrivate());
ka.doPhase(bob.getPublic(), true);
byte[] shared = ka.generateSecret();       // raw 32-byte secret; run through a KDF
```

### ML-DSA (post-quantum signature — JSL only)

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "JSL");
KeyPair kp = kpg.generateKeyPair();        // no SecureRandom → strength auto-selected

Signature s = Signature.getInstance("ML-DSA-65", "JSL");
s.initSign(kp.getPrivate()); s.update(message); byte[] sig = s.sign();
s.initVerify(kp.getPublic()); s.update(message); boolean ok = s.verify(sig);
```

### Digest, HMAC, KDF

```java
byte[] h = MessageDigest.getInstance("SHA2-256", "JSL").digest(data);   // or "SHA-256"

Mac mac = Mac.getInstance("HmacSHA256", "JSL");
mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
byte[] tag = mac.doFinal(data);

SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "JSL");
byte[] dk = pbkdf2.generateSecret(
        new PBEKeySpec(password, salt, 600_000, 256)).getEncoded();
```

## When you are unsure

1. Check availability at runtime: `Security.getProvider("JSL").getService("Cipher", "AES/GCM/NoPadding")`, or consult `SERVICES.md`.
2. If an algorithm isn't in `SERVICES.md` for the chosen provider, it is not registered — do not fabricate a transformation string; pick a registered one or tell the user it is unsupported.
3. For anything about building, contributing, or internal design, that is out of scope here — point to the Jostle repo's `README.md` and `CONTRIBUTING.md`.
