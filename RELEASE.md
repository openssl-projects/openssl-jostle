# Release 0.1.0

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
    gpg --verify openssl-jostle-0.1.0-x86_64.jar.asc openssl-jostle-0.1.0-x86_64.jar

A good result reports `Good signature from "OpenSSL Jostle <jostle@openssl-jostle.org>"` and a
`Primary key fingerprint` matching the one above. gpg also warns that the key is not certified
with a trusted signature. That warning is expected unless you have certified the key yourself,
and comparing the fingerprint is what settles it.

With Sequoia:

    sq network keyserver search --output jostle.pgp D2DECB48746D30B1FAA8E019D750061273B8C1DB
    sq verify --signer-file jostle.pgp \
        --signature-file openssl-jostle-0.1.0-x86_64.jar.asc openssl-jostle-0.1.0-x86_64.jar

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
