---
name: rebuild_no_test
description: Rebuild the Jostle jar end to end — regenerate JNI headers, recompile the native interface libraries for both the nonfips and fips trees, then assemble the multi-release jar — while skipping all tests. Use this skill whenever the user wants a fresh jar built without running the suite, including phrases like "rebuild the jar", "rebuild with new native binaries", "build but skip the tests", "rebuild no test", "give me a fresh jar", "rebuild the native libs and jar", "build for staging into the bc repo". Also use it after editing anything under interface/ (a gradle-only build does NOT recompile C), or before staging the jar into openssl-jostle-extensions-bc.
---

# Rebuild the jar (native + Java), no tests

Three stages, in order. **The order matters and the Gradle-only path is not
enough**: `./gradlew build` never recompiles the C, so a jar built without
stage 2 silently ships the *previous* native libraries. That is the single most
common way to "fix" a C bug and then watch the old behaviour persist.

```
gradlew clean compileJava   ->  regenerates JNI headers from current Java sources
interface/build.sh          ->  compiles 4 .dylib/.so into src/main/resources/native/<os>/<arch>
gradlew build -x test       ->  assembles the multi-release jar around those libs
```

## Environment

Both variables are mandatory; `interface/build.sh` exits non-zero with a clear
message if either is unset.

```bash
export JAVA_HOME="$BC_JDK25"                                   # must be Java 25
export PATH="$JAVA_HOME/bin:$PATH"
export OPENSSL_PREFIX=/Users/meganwoods/openssl/jostle/openssls/osx/arm64
```

`OPENSSL_PREFIX` points at a built mainline OpenSSL 3.x tree — the repo
convention is `../openssls/<os>/<arch>` relative to the checkout. On this
machine `JAVA_HOME` is normally unset in fresh shells and `java` is not on
`PATH` at all, so **always export both explicitly**; a bare `./gradlew` fails
with "Unable to locate a Java Runtime".

Do NOT set `JOSTLE_OPS_TEST` for this build. It is only for OPS
fault-injection runs, and a jar built with it is not the one to stage or ship.
(Consequence: every `*OpsTest` assumption-skips against this jar — expected,
not a failure.)

## Run

```bash
cd <repo root>

# Stage 1 — JNI headers from current Java sources.
./gradlew clean compileJava

# Stage 2 — native interface: builds interface_jni, interface_ffi,
# interface_fips_jni, interface_fips_ffi and installs them into
# jostle/src/main/resources/native/<os>/<arch>.
./interface/build.sh

# Stage 3 — jar, tests skipped.
./gradlew build -x test
```

Stage 2 is the slow one (cmake + full C rebuild of both trees); stages 1 and 3
are seconds when warm.

## Verify before handing the jar on

The build succeeding is not proof the jar picked up your native change, so
check all three:

1. **Four libraries installed.** Stage 2's tail must show four `-- Installing:`
   lines — `libinterface_jni`, `libinterface_ffi`, `libinterface_fips_jni`,
   `libinterface_fips_ffi`. Fewer means a tree failed to build.
2. **Jar is newer than the libraries.**
   `ls -l jostle/build/libs/openssl-jostle-*.jar` against
   `ls -l jostle/src/main/resources/native/<os>/<arch>/`.
3. **Loader smoke test** — the jar loads its own natives:

```bash
java --module-path jostle/build/libs/openssl-jostle-0.1-SNAPSHOT.jar \
     --module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo
```

Expect `Load Successful: true` and `Loader Message: Loader Finished
Successfully`. A `false` here means the jar shipped without usable natives —
stop, do not stage it. (`--services` additionally lists every registered
algorithm, useful when the rebuild followed a registration change.)

## Staging into openssl-jostle-extensions-bc

That repo consumes the jar from `libs/` and the build does **not** copy it, so
it must be overwritten by hand:

```bash
cp jostle/build/libs/openssl-jostle-0.1-SNAPSHOT.jar \
   ../openssl-jostle-extensions-bc/libs/openssl-jostle-0.1-SNAPSHOT.jar
shasum jostle/build/libs/openssl-jostle-0.1-SNAPSHOT.jar \
       ../openssl-jostle-extensions-bc/libs/openssl-jostle-0.1-SNAPSHOT.jar
```

Compare the two hashes and quote the value — it is what lets the other side
confirm which artifact they tested. Overwriting a file in another repository is
outward-facing: confirm with the user first unless they asked for the staging
in this turn.

## Do not claim this build is verified

This skill deliberately skips the suite, so the jar is **unverified**. Say so
when handing it over. When the user wants confidence, follow with the full
matrix — see the `verify-test-matrix` skill — remembering that `TEST_FIPS_LIB`
is not a Gradle task input, so a cached green run can replay wholesale-skipped
FIPS classes and must be forced with `--rerun-tasks`.
