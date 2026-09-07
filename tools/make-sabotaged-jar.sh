#!/usr/bin/env bash
#
# Build a copy of the jar whose module descriptor has its `provides
# java.security.Provider` line REMOVED, so the discriminating power of
# tools/ModulePathCheck.java can be re-proven after any descriptor change.
#
# ModulePathCheck's ServiceLoader-by-name assertion is the ONLY one that sees
# this: discovery drops JSL and JSLFIPS (9 providers to 7) while the other
# checks are unchanged.
#
# usage: tools/make-sabotaged-jar.sh <out.jar> [in.jar]
# env:   JAVA_HOME  a JDK 9+ (javac must compile a module descriptor)
set -eu

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR/.." || exit 3

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <out.jar> [in.jar]" >&2
  exit 2
fi
# Absolute from here on: later steps cd, and a relative path silently wrote
# nothing while still reporting success.
case "$1" in
  /*) OUT="$1" ;;
  *)  OUT="$PWD/$1" ;;
esac

if [ -z "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME must be set" >&2
  exit 2
fi
JH="$JAVA_HOME"
if [ ! -x "$JH/bin/javac" ] && [ -x "$JH/Contents/Home/bin/javac" ]; then
  JH="$JH/Contents/Home"
fi

if [ "$#" -ge 2 ]; then
  IN="$2"
else
  version=$(grep '^version=' gradle.properties | sed -e 's/version=//')
  IN="jostle/build/libs/openssl-jostle-${version}.jar"
fi
[ -f "$IN" ] || { echo "jar not found: $IN" >&2; exit 2; }
case "$IN" in
  /*) ;;
  *)  IN="$PWD/$IN" ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The classes must be present for javac to validate the descriptor's exports,
# and the java9 overrides must be flattened over the baseline so every exported
# package resolves.
mkdir -p "$WORK/ext"
( cd "$WORK/ext" && unzip -q "$IN" )
cp -R "$WORK/ext/META-INF/versions/9/." "$WORK/ext/" 2>/dev/null || true

grep -vE 'provides java\.security\.Provider|JostleFIPSProvider;' \
  jostle/src/main/java9/module-info.java > "$WORK/module-info.java"
if grep -q 'provides' "$WORK/module-info.java"; then
  echo "sabotage did not remove the provides directive - check module-info.java" >&2
  exit 1
fi

# --release 9 gives class-file 53, matching the real descriptor; a JDK-25
# default (69) is unreadable on JDK 17 and fails for the wrong reason.
"$JH/bin/javac" --release 9 -d "$WORK/ext" --class-path "$WORK/ext" \
  "$WORK/module-info.java"

# Replace ONE entry in a copy: rebuilding the jar loses `Multi-Release: true`
# and the module then vanishes entirely.
cp "$IN" "$OUT"
mkdir -p "$WORK/swap/META-INF/versions/9"
cp "$WORK/ext/module-info.class" "$WORK/swap/META-INF/versions/9/"
( cd "$WORK/swap" && zip -q "$OUT" META-INF/versions/9/module-info.class )

echo "sabotaged jar written: $OUT"
