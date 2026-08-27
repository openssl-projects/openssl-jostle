#!/usr/bin/env bash
#
# Run the full test matrix once per FIPS module CONFIGURATION, not just once.
#
# JSLFIPS ships one build that must serve modules which disagree in both
# directions, and most of that disagreement is fipsinstall CONFIG rather than
# module version (see the "A FIPS module's strictness is mostly fipsinstall
# CONFIG" section of .claude/guides/testing.md). A single-config green run is
# therefore not evidence the contract holds: the 3.5.x capability gates never
# fire at default settings, so the suite passes without executing the code
# under test.
#
# Each configuration is run by swapping fipsmodule.cnf into place, invoking
# run-matrix.sh, and restoring the original cnf afterwards - on any exit path,
# including Ctrl-C, because the cnf belongs to a shared OpenSSL install.
#
# Required env:
#   JAVA_HOME            Java 25 JDK
# Configuration list:
#   JOSTLE_FIPS_CONFIGS  one entry per line: name|module_path|cnf_path
#                        cnf_path may be empty to use the install's own cnf.
#                        Unset => discover every module under
#                        ${JOSTLE_OPENSSLS_DIR:-$HOME/openssl/openssls} and run
#                        each with its installed cnf.
#
# JOSTLE_SWEEP_DRYRUN=1 exercises discovery, the cnf swap and the restore
# without running the matrix. It reports "NOT verified" and must never be
# mistaken for a passing sweep.
#
# Prints the distinguishing switches of each cnf before running it, so the
# transcript records WHICH configuration was actually tested rather than
# leaving it to be inferred.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR/../../../.." || exit 3

if [ -z "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME must point at a Java 25 JDK" >&2
  exit 2
fi

if [ -z "${JOSTLE_FIPS_CONFIGS:-}" ]; then
  ROOT="${JOSTLE_OPENSSLS_DIR:-$HOME/openssl/openssls}"
  JOSTLE_FIPS_CONFIGS=$(find "$ROOT" -maxdepth 4 \
      \( -name 'fips.dylib' -o -name 'fips.so' \) 2>/dev/null |
    while read -r m; do
      n=$(basename "$(dirname "$(dirname "$(dirname "$m")")")")
      printf '%s|%s|\n' "$n" "$m"
    done)
  if [ -z "$JOSTLE_FIPS_CONFIGS" ]; then
    echo "no FIPS modules found under $ROOT; set JOSTLE_FIPS_CONFIGS" >&2
    exit 2
  fi
  echo "discovered configurations (set JOSTLE_FIPS_CONFIGS to be explicit):"
  echo "$JOSTLE_FIPS_CONFIGS" | sed 's/^/  /'
fi

# Restore every cnf we overwrite, whatever happens.
#
# ONE backup per target, taken the FIRST time that target is swapped, so the
# restore always writes the install's ORIGINAL content back. Two configs
# routinely target the same install - 3.5.8-default and 3.5.8-pedantic both
# swap openssls/osx_3_5_8/.../fipsmodule.cnf - and a per-swap backup would
# capture the PREVIOUS config's cnf on the second pass and restore that,
# leaving the install silently holding the wrong strictness. That is worse
# than untidy: the pedantic-only gates (no-short-mac, dsa-sign-disabled,
# hmac-key-check, ...) then never fire in any later run, which is exactly the
# "green without executing the code under test" failure this script exists to
# prevent. Observed for real on 2026-08-23, from a dry run.
declare -a BACKUPS=()
backup_once () {
  local target="$1" pair b
  for pair in "${BACKUPS[@]:-}"; do
    [ -n "$pair" ] || continue
    if [ "${pair##*::}" = "$target" ]; then
      return 0    # already have this target's ORIGINAL content
    fi
  done
  b=$(mktemp); cp "$target" "$b"; BACKUPS+=("$b::$target")
}
restore () {
  for pair in "${BACKUPS[@]:-}"; do
    [ -n "$pair" ] || continue
    cp "${pair%%::*}" "${pair##*::}" 2>/dev/null
  done
  [ "${#BACKUPS[@]}" -gt 0 ] && echo "restored ${#BACKUPS[@]} fipsmodule.cnf file(s)"
}
trap restore EXIT INT TERM

FAILED=()
PASSED=()

while IFS='|' read -r NAME MODULE CNF; do
  [ -n "${NAME:-}" ] || continue
  echo
  echo "################ $NAME ################"
  if [ ! -f "$MODULE" ]; then
    echo "  module missing: $MODULE — SKIPPED (not a pass)" >&2
    FAILED+=("$NAME (module missing)")
    continue
  fi

  # The module reads fipsmodule.cnf from the install; keep every copy in step.
  PREFIX=$(dirname "$(dirname "$(dirname "$MODULE")")")
  TARGETS=$(find "$PREFIX" -name 'fipsmodule.cnf' 2>/dev/null)
  if [ -n "$CNF" ]; then
    if [ ! -f "$CNF" ]; then
      echo "  cnf missing: $CNF — SKIPPED (not a pass)" >&2
      FAILED+=("$NAME (cnf missing)")
      continue
    fi
    for t in $TARGETS; do
      backup_once "$t"
      cp "$CNF" "$t"
    done
  fi

  # Record what is actually in force - this is the line that makes a green run
  # mean something, since the switches decide whether the gates fire at all.
  ONE=$(echo "$TARGETS" | head -1)
  echo "  cnf: $ONE"
  # Captured first, NOT piped straight into sed: a pipeline's exit status is
  # the LAST command's, so `grep ... | sed ... || echo "(none)"` never fires
  # the fallback - sed succeeds even when grep matched nothing. The symptom is
  # a config whose switch block prints nothing at all, which reads as "the
  # check did not run" rather than "this cnf carries none of them". Seen for
  # real on the 3.1.2 config, 2026-08-24.
  SWITCHES=$(grep -E '^(dsa-sign-disabled|rsa-pkcs15-pad-disabled|hmac-key-check|kmac-key-check|no-short-mac|signature-digest-check|kbkdf-key-check|sskdf-key-check|sskdf-digest-check|sshkdf-key-check|sshkdf-digest-check)' \
       "$ONE" 2>/dev/null)
  if [ -n "$SWITCHES" ]; then
    echo "$SWITCHES" | sed 's/^/    /'
  else
    echo "    (none of the tracked switches present)"
  fi

  if [ -n "${JOSTLE_SWEEP_DRYRUN:-}" ]; then
    # Plumbing check: prove discovery, the cnf swap and the restore work
    # without a 30-minute run. Never counts as verification.
    echo "  DRY RUN: would run the matrix with TEST_FIPS_LIB=$MODULE"
    PASSED+=("$NAME (dry run - NOT verified)")
    continue
  fi
  TEST_FIPS_LIB="$MODULE" bash "$SCRIPT_DIR/run-matrix.sh"
  if [ $? -eq 0 ]; then PASSED+=("$NAME"); else FAILED+=("$NAME"); fi
done <<< "$JOSTLE_FIPS_CONFIGS"

echo
echo "################ sweep summary ################"
for n in "${PASSED[@]:-}"; do [ -n "$n" ] && echo "  PASS  $n"; done
for n in "${FAILED[@]:-}"; do [ -n "$n" ] && echo "  FAIL  $n"; done
[ "${#FAILED[@]}" -eq 0 ] || exit 1
echo "all configurations verified"
