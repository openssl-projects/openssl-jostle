#!/usr/bin/env bash
#
# Run ModulePathCheck against the built jar on the MODULE PATH, then DumpInfo.
#
# One script, two callers: build_osx.sh and the CI module-path cells, so a local
# run and CI witness the same thing. The module descriptor lives only in
# META-INF/versions/9, nothing in the test matrix puts jostle on the module
# path, and only the ServiceLoader-by-name assertion in ModulePathCheck can see
# a broken `provides` line - see that file's header.
#
# usage: tools/check-module-path.sh [jar]
#   jar  defaults to the version named in gradle.properties
# env:
#   JAVA_HOME  the JDK to run under (required; 11+ for the module path)
set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR/.." || exit 3

if [ -z "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME must be set" >&2
  exit 2
fi

# A BC_JDK-style root may be flat or a macOS bundle.
JH="$JAVA_HOME"
if [ ! -x "$JH/bin/java" ] && [ -x "$JH/Contents/Home/bin/java" ]; then
  JH="$JH/Contents/Home"
fi
if [ ! -x "$JH/bin/java" ]; then
  echo "no bin/java under $JAVA_HOME" >&2
  exit 2
fi

if [ "$#" -ge 1 ]; then
  JAR="$1"
else
  version=$(grep '^version=' gradle.properties | sed -e 's/version=//')
  JAR="jostle/build/libs/openssl-jostle-${version}.jar"
fi
if [ ! -f "$JAR" ]; then
  echo "jar not found: $JAR (run ./gradlew :jostle:jar)" >&2
  exit 2
fi

echo "=== module-path check: $("$JH/bin/java" -version 2>&1 | head -1) ==="
echo "    jar: $JAR"

# `|| rc=$?` because set -e would otherwise exit here and DumpInfo would not
# run - and its output is most useful precisely when the check has failed.
rc=0
"$JH/bin/java" --module-path "$JAR" \
  --add-modules org.openssl.jostle.prov \
  --enable-native-access=org.openssl.jostle.prov \
  "$SCRIPT_DIR/ModulePathCheck.java" || rc=$?

echo "=== DumpInfo through the module path ==="
"$JH/bin/java" --module-path "$JAR" \
  --enable-native-access=org.openssl.jostle.prov \
  --module org.openssl.jostle.prov/org.openssl.jostle.util.DumpInfo || true

exit $rc
