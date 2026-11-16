# Release 0.3.0

This release of OpenSSL Jostle, a Java JCA/JCE provider that delegates its cryptography to
OpenSSL through a native interface, adds services met while BouncyCastle's extension suites
were brought to 1.87, and makes PKIX path building and validation independent of the order of
the caller's stores.

- Two providers: `JSL`, backed by the OpenSSL default provider, and `JSLFIPS`, backed by the
  OpenSSL FIPS provider with the 3.1.2 and 3.5.9 modules supported.
- Built against OpenSSL 3.5.9.
- Runs on Java 8 to Java 25: the JNI bridge on every JDK, the FFM bridge on Java 25. Building
  needs Java 25.
- Published as `org.openssl.jostle:openssl-jostle:0.3.0` with a classifier per architecture,
  `x86_64` or `aarch64`. Each bundle is a self-contained multi-release jar holding that
  architecture's native libraries: Linux (glibc 2.28 or later) and macOS 14 or later in both,
  and Windows in the `x86_64` bundle.
- Licensed under the Apache License 2.0.

What changed since 0.2.0:

- ChaCha20 takes an initial block counter: through the JDK's `ChaCha20ParameterSpec` on Java 11
  and later, and through Jostle's `ChaCha20CounterParameterSpec`
  (`org.openssl.jostle.jcajce.spec`) on every Java version. A stream that would pass the RFC 8439
  limit for one nonce is refused with an IllegalStateException.
- A key agreement asked for its secret before its last phase refuses with an
  IllegalStateException.
- A GMAC whose init is refused for a reused key and nonce stays unusable until an init succeeds.
- The bare `ML-DSA` key pair generator defaults to ML-DSA-65 (it was ML-DSA-87).
- The ML-KEM KeyGenerator accepts a key from another provider by its encoding.
- The GCM, CCM and ChaCha20-Poly1305 AlgorithmParameters accept Jostle's `AEADParameterSpec`
  (`org.openssl.jostle.jcajce.spec`) and keep its tag length.
- Cofactor ECDH is served by both providers under `ECCDH`, `ECDHC` and the `ECCDHwithSHA*KDF`
  names with their RFC 5753 object identifiers, and the `ECCDHwithSHA*CKDF` agreements are
  computed with it. On curves with cofactor 1 the results are unchanged.
- `JSL` serves the RFC 3217 Triple-DES key wrap as `DESedeWrap` and under its object
  identifier. The key-encryption key is 24 bytes, and an IV supplied by the caller is refused.
- A padding name on a key-wrap transformation is refused with a NoSuchPaddingException; use
  `NoPadding` or the dedicated wrap name. With no provider named, `AES/KW/PKCS5Padding` is
  then served by the JDK on Java 17 and later, whose result differs from what 0.2.0 produced
  under that name, so a key wrapped by 0.2.0 under it is not recovered that way; on Java 8 and 11
  no provider serves the name; unwrap such a key with `AES/KW/NoPadding` or `AESWrap`.
- `JSL` serves the `Collection` CertStore, a live view of the caller's collection.
- The PKIX path builder tries the alternative issuers of a cross-certified CA, within stated
  bounds, and returns the same path whatever the order of the caller's stores. A candidate path
  beyond the maximum length, or a target that is itself a trust anchor, is passed over and the
  build goes on to the next candidate.
- The PKIX validator and builder hand OpenSSL the stores' certificates and CRLs in one
  order, so neither answer depends on the order of the caller's stores. Where two CRLs that
  OpenSSL ranks equally carry the same issue time, the one listing a certificate of the path is
  the one consulted; of the delta CRLs for one base, the newest that is current.
- A CertStore that cannot be read makes the build or validation fail with a
  CertPathBuilderException or CertPathValidatorException carrying the cause (it was an
  InvalidAlgorithmParameterException). A RuntimeException thrown by a store passes through
  unchanged.
- BouncyCastle 1.87 is the reference the agreement tests compare against.

Where to look next:

- `README.md`: building, installing, and the loader properties.
- `SERVICES.md`: every service each provider registers.
- `docs/jostle-ai-guide.md`: runnable worked examples for JSL and JSLFIPS.

## Verifying releases

Every release is signed with the OpenSSL Jostle release key:

    OpenSSL Jostle <jostle@openssl-jostle.org>
    ECDSA P-384
    D2DE CB48 746D 30B1 FAA8  E019 D750 0612 73B8 C1DB

That is the fingerprint of the primary key, which is used only for certification. The
signatures themselves are made by a signing subkey of that primary key. The subkey is
replaced from time to time, and gpg and sq follow it automatically, so check the primary
fingerprint above rather than the subkey. This file is the reference for the fingerprint: it is
versioned and reviewed, which a release page is not.

Each release contains the provider jars `openssl-jostle-<version>-x86_64.jar` and
`openssl-jostle-<version>-aarch64.jar`, plus `openssl-jostle-<version>-sources.jar`,
`openssl-jostle-<version>-javadoc.jar` and `openssl-jostle-<version>.pom`. Each of those five
files has a detached signature with the same name plus `.asc`. A single `SHA256SUMS` file covers
all ten. The same files are published to Maven Central.

The certificate is on keys.openpgp.org. With GnuPG:

    gpg --keyserver hkps://keys.openpgp.org --recv-keys D2DECB48746D30B1FAA8E019D750061273B8C1DB
    gpg --verify openssl-jostle-0.3.0-x86_64.jar.asc openssl-jostle-0.3.0-x86_64.jar

A good result reports `Good signature from "OpenSSL Jostle <jostle@openssl-jostle.org>"` and a
`Primary key fingerprint` matching the one above. gpg also warns that the key is not certified
with a trusted signature. That warning is expected unless you have certified the key yourself,
and comparing the fingerprint is what settles it.

With Sequoia:

    sq network keyserver search --output jostle.pgp D2DECB48746D30B1FAA8E019D750061273B8C1DB
    sq verify --signer-file jostle.pgp \
        --signature-file openssl-jostle-0.3.0-x86_64.jar.asc openssl-jostle-0.3.0-x86_64.jar

To check the whole download at once, run this in the directory holding the files:

    sha256sum -c SHA256SUMS

`SHA256SUMS` catches a corrupted or incomplete download. It is not a second security check,
because it is published alongside the files it covers. The `.asc` signatures are what prove where
the files came from.

The provider jars also carry a JCE code signature inside the jar (`META-INF/JOSTLE-J.SF`). It
chains to Oracle's JCE Code Signing CA, carries an RFC 3161 timestamp, and is what allows Oracle
JDK to load Jostle as a JCE provider. OpenJDK does not require provider signing. You do not need
a second key for it. On a stock OpenJDK, `jarsigner -verify` prints `jar verified.` together with
a PKIX path-building warning. That warning is expected, because Oracle's JCE root is not in
OpenJDK's `cacerts`.

## Release 0.2.0

This release of OpenSSL Jostle, a Java JCA/JCE provider that delegates its cryptography to
OpenSSL through a native interface, moves the build to OpenSSL 3.5.9.

- Two providers: `JSL`, backed by the OpenSSL default provider, and `JSLFIPS`, backed by the
  OpenSSL FIPS provider with the 3.1.2 and 3.5.9 modules supported. The 3.5.8 module, supported
  in 0.1.0, is replaced by 3.5.9.
- Built against OpenSSL 3.5.9.
- Runs on Java 8 to Java 25: the JNI bridge on every JDK, the FFM bridge on Java 25. Building
  needs Java 25.
- Published as `org.openssl.jostle:openssl-jostle:0.2.0` with a classifier per architecture,
  `x86_64` or `aarch64`. Each bundle is a self-contained multi-release jar holding that
  architecture's native libraries: Linux (glibc 2.28 or later) and macOS 14 or later in both,
  and Windows in the `x86_64` bundle.
- Licensed under the Apache License 2.0.

What changed since 0.1.0:

- Native inputs are further length-checked on both bridges, and inputs outside the checked
  bounds are refused with the standard JCA exception types; secret copies are cleared after use;
  native handles carry their type.
- A certificate or CRL above the configured size ceiling is refused with a CertificateException.
- DH public values are checked against their group at import, including the subgroup of a
  named group.
- Certificate path validation enforces policy constraints, returns the PKIX policy tree and
  reports refusals with the JDK's reasons.
- Certificate and CRL verification falls back to the JCA provider search order when the bound
  provider does not supply the signature algorithm (issue 63).
- The multi-release jar holds the base classes at its root only, not under `META-INF/versions/9`.
- The repository carries the DHX and RSA-KEM OpenSSL probes under `probes/`.

## Release 0.1.0

This is the initial release of OpenSSL Jostle, a Java JCA/JCE provider that delegates its
cryptography to OpenSSL through a native interface.

- Two providers: `JSL`, backed by the OpenSSL default provider, and `JSLFIPS`, backed by the
  OpenSSL FIPS provider with the 3.1.2 and 3.5.8 modules supported.
- Built against OpenSSL 3.5.8.
- Runs on Java 8 to Java 25: the JNI bridge on every JDK, the FFM bridge on Java 25. Building
  needs Java 25.
- Published as `org.openssl.jostle:openssl-jostle:0.1.0` with a classifier per architecture,
  `x86_64` or `aarch64`. Each bundle is a self-contained multi-release jar holding that
  architecture's native libraries: Linux (glibc 2.28 or later) and macOS 14 or later in both,
  and Windows in the `x86_64` bundle.
- Licensed under the Apache License 2.0.
