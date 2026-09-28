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
