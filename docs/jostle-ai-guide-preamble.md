# OpenSSL Jostle: worked examples

OpenSSL Jostle is a JCA/JCE provider that delegates its cryptography to OpenSSL through a native library. The
jar is built on Java 25 and runs on Java 8 to 25. Every example in this guide is a JUnit test that runs against
the built jar, from a package outside it, so the code shown is code that works and uses only the exported API.

## The two providers

1. `JSL` (`org.openssl.jostle.jcajce.provider.JostleProvider`) runs on the OpenSSL bundled in the jar.
2. `JSLFIPS` (`org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider`) runs on an OpenSSL FIPS provider
   module you supply. It registers nothing until it is configured.

Both can be registered in one JVM; each runs on its own native library and OpenSSL library context, and JCA
registration order decides which one an unqualified `getInstance` picks. A key object belongs to the provider
instance that made it; to move a key between the two, encode it with `getEncoded()` and decode it through the
other provider's `KeyFactory`.

```java
Security.addProvider(new JostleProvider());
Security.addProvider(new JostleFIPSProvider("fips_module=/opt/openssl-fips/lib/ossl-modules/fips.so"));
```

## Configuring JSLFIPS

The configuration string is a comma-separated `key=value` list:

1. `fips_module` (required): the path to the FIPS module file.
2. `fips_config` (optional): the fipsinstall-generated configuration; by default `fipsmodule.cnf` next to the
   module.

A value may be quoted with `"`, `'` or a backtick, and may use a scheme: `env:NAME` (an environment
variable), `prop:NAME` (a `java.security` property, or else a system property), `file:URI` (a file URI,
resolved to its path) or `str:TEXT` (the text as written). A value without a scheme is used as written.
The string can also be passed to `configure(String)`, set as a static registration argument in
`java.security`, or given to the no-argument constructor through the `org.openssl.jostle.fips.config`
property. Initialisation is once per JVM: constructing a second provider with the same configuration does
nothing, and a different configuration throws `IllegalStateException`.

The JSLFIPS examples describe the 3.5.8 module. What a module serves depends on its version, and some of its
strictness depends on how it was installed (`openssl fipsinstall`); the examples say which is which.

## Running

Jostle loads a native library, so from JDK 24 the JVM warns unless native access is enabled for it:

```
# jar on --module-path (the module is org.openssl.jostle.prov; JDK 11 or later)
--enable-native-access=org.openssl.jostle.prov

# jar on -classpath
--enable-native-access=ALL-UNNAMED
```

JDK 11 rejects the flag; JDK 17 to 23 accept it and need nothing. The loader reads these system properties:

1. `org.openssl.jostle.loader.install_dir`: where the native libraries are extracted, by default the temporary
   directory. Set it when that directory is on a filesystem mounted `noexec`, since the operating system refuses
   to load a native library from there.
2. `org.openssl.jostle.loader.interface`: `auto` (the default), `ffm`, `jni` or `none`. Under `auto` the
   loader uses FFM on Java 25 and JNI on every other JDK.
3. `org.openssl.jostle.loader.extract_openssl`: `false` stops the loader extracting the bundled OpenSSL, for
   when it is loaded from elsewhere.

`org.openssl.jostle.util.DumpInfo` prints the provider, platform, JVM, the interface chosen and the libraries
loaded; see `README.md`. `SERVICES.md` lists every registered name.

## Using this guide with an AI coding assistant

Reference this file from your assistant's instruction file (`CLAUDE.md`, `AGENTS.md`,
`.github/copilot-instructions.md` or similar) and ask it to follow the examples. Everything below the marker
is generated from the example classes under `jostle/src/test/examples`, and a test fails the build when the
two differ.
