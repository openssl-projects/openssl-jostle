#!/usr/bin/env python3
"""
find-missing-jni-ops.py — scan Jostle JNI bridge sources for calls into
the JVM (or the project's JNI helper layer) whose return values are
checked in an if-statement but lack an `OPS_*` fault-injection macro on
the check. The canonical macro for JNI access faults is
`OPS_FAILED_ACCESS_N`, defined in `interface/util/ops.h`.

A "missing OPS" finding looks like one of these patterns where the
if-statement has no `OPS_*` macro prefixing the condition:

    name = (*env)->GetStringUTFChars(env, _name, NULL);
    if (name == NULL) { ... }              (after-assign, NULL check)

    if (!load_bytearray_ctx(&out, env, _out)) { ... }   (direct, bool check)

    if ((*env)->NewByteArray(env, len) == NULL) { ... }  (direct, NULL check)

The script intentionally over-reports. False positives are easier to
dismiss than silent gaps. Suppress a finding by either:
  - adding an OPS macro to the check (the recommended fix), or
  - adding the function name to NEVER_FAILS below if it truly can't fail.

Usage:
    find-missing-jni-ops.py [paths ...]

Default scan path: interface/jni/*.c relative to CWD.
Exit code: 0 if no findings, 1 otherwise.
"""

import re
import sys
from pathlib import Path

# JNI helper functions (project-internal, defined in
# interface/jni/bytearrays.{c,h} and byte_array_critical.{c,h}) whose
# failure means a JNI access fault. The OPS_FAILED_ACCESS_* macros
# typically wrap these.
JNI_HELPERS = {
    "load_bytearray_ctx",
    "load_critical_ctx",
    "load_bytearray_new",
    "check_bytearray_in_range",
    "check_critical_in_range",
}

# Direct JVM JNI calls (invoked as `(*env)->FuncName(env, ...)`) that
# can fail and whose failure needs `OPS_FAILED_ACCESS_*` instrumentation
# when checked.
JVM_JNI_CALLS = {
    # Byte-array access — return NULL on OOM.
    "GetByteArrayElements",
    "GetPrimitiveArrayCritical",
    "NewByteArray",
    # String access — return NULL on OOM.
    "GetStringUTFChars",
    "GetStringChars",
    # Class / method / field reflection — return NULL on failure.
    "FindClass",
    "GetMethodID", "GetStaticMethodID",
    "GetFieldID", "GetStaticFieldID",
    # Object access — can return NULL or fail.
    "NewObject", "NewObjectArray",
    "GetObjectField", "GetStaticObjectField",
    "GetObjectArrayElement",
    # Up-calls that return references (the int variants don't surface
    # NULL but the object variants do).
    "CallObjectMethod", "CallStaticObjectMethod",
    "CallObjectMethodA", "CallStaticObjectMethodA",
    "CallObjectMethodV", "CallStaticObjectMethodV",
    # Local/global ref creation — return NULL on OOM.
    "NewLocalRef", "NewGlobalRef", "NewWeakGlobalRef",
    # JVM attach/detach — return JNI_OK / non-zero.
    "AttachCurrentThread", "AttachCurrentThreadAsDaemon",
    # Int-array equivalents (less common but used).
    "GetIntArrayElements", "GetLongArrayElements",
    "NewIntArray", "NewLongArray",
}

# Functions that never fail (cleanup, getters that return void or
# always succeed). The script silently filters these out before flagging.
NEVER_FAILS = {
    # Project-internal init/release — null-safe by design.
    "init_bytearray_ctx", "init_critical_ctx",
    "release_bytearray_ctx", "release_critical_ctx",
    # JVM release / cleanup — return void or always succeed.
    "ReleaseByteArrayElements", "ReleasePrimitiveArrayCritical",
    "ReleaseStringUTFChars", "ReleaseStringChars",
    "ReleaseIntArrayElements", "ReleaseLongArrayElements",
    "DeleteLocalRef", "DeleteGlobalRef", "DeleteWeakGlobalRef",
    # JVM length / size getters — don't fail in the audit sense.
    "GetArrayLength",
    "GetStringUTFLength", "GetStringLength",
    # Exception inspection — return state, not error codes for our purposes.
    "ExceptionCheck", "ExceptionOccurred",
    "ExceptionClear", "ExceptionDescribe",
    # JVM attach support functions that always succeed for our use.
    "DetachCurrentThread",
    # GetEnv — returns JNI_OK / JNI_EDETACHED; failure handling sits
    # at a different layer (rand_upcall has its own OPS_THREAD_ATTACH).
    "GetEnv",
    # IsSameObject, IsInstanceOf — discriminators, not error returns.
    "IsSameObject", "IsInstanceOf",
}

# Combined set used for "is this a JNI access call worth auditing".
ALL_JNI_ACCESS = JNI_HELPERS | JVM_JNI_CALLS


def find_jni_access_calls(text):
    """Return the set of JNI access function names called in `text`.

    Matches both styles:
      - `(*env)->FuncName(env, ...)` for direct JVM calls.
      - `load_bytearray_ctx(...)` etc. for project-internal helpers.
    """
    funcs = set()
    # `(*env)->FuncName(` style.
    for m in re.finditer(r"\(\s*\*\s*env\s*\)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        funcs.add(m.group(1))
    # Bare identifier `FuncName(` — includes both project helpers and any
    # `(*env)->X` whose `(*env)->` may have been split across the previous
    # line in collected multi-line text.
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        funcs.add(m.group(1))
    return funcs & ALL_JNI_ACCESS


def collect_if_condition(lines, start_line_idx):
    """Collect a (possibly multi-line) if-statement condition.

    `start_line_idx` should be the index of a line containing `if (`. Returns
    (condition_text, end_line_idx) where condition_text is the interior of
    the outermost if(...) parens, and end_line_idx is the line holding the
    closing paren.
    """
    line = lines[start_line_idx]
    m = re.search(r"\bif\s*\(", line)
    if not m:
        return None
    depth = 1
    out = []
    line_idx = start_line_idx
    char_idx = m.end()
    while line_idx < len(lines):
        cur = lines[line_idx]
        while char_idx < len(cur):
            ch = cur[char_idx]
            if ch == "(":
                depth += 1
                out.append(ch)
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return ("".join(out), line_idx)
                out.append(ch)
            else:
                out.append(ch)
            char_idx += 1
        out.append("\n")
        line_idx += 1
        char_idx = 0
    return ("".join(out), line_idx - 1)


def previous_nonblank_noncomment(lines, idx):
    """Return (line_index, stripped_line) for the line above idx that is
    non-blank and not a pure comment line. Returns (None, None) if none."""
    i = idx - 1
    while i >= 0:
        s = lines[i].strip()
        if s and not s.startswith("//") and not s.startswith("/*") and not s.startswith("*"):
            return (i, s)
        i -= 1
    return (None, None)


def scan_file(path):
    """Yield (path, line_no, funcs, snippet, reason) for each finding."""
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        return
    lines = text.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        # Match an `if (` at the start of a (potentially indented) line.
        if re.match(r"\s*if\s*\(", line):
            collected = collect_if_condition(lines, i)
            if collected is None:
                i += 1
                continue
            cond, end_idx = collected
            next_i = end_idx + 1

            funcs_in_cond = find_jni_access_calls(cond)
            funcs_to_audit = set()
            reason = None

            if funcs_in_cond:
                funcs_to_audit = funcs_in_cond
                reason = "direct"
            else:
                # After-assign: previous non-blank line was an assignment
                # from a JNI access function, and this if-line checks
                # the assigned variable (== NULL, != NULL, == 0, ...).
                prev_idx, prev_line = previous_nonblank_noncomment(lines, i)
                if prev_line is not None:
                    prev_calls = find_jni_access_calls(prev_line)
                    if prev_calls:
                        if re.search(r"(==|!=|<|>|>=|<=)\s*(NULL|0|JNI_OK)", cond):
                            funcs_to_audit = prev_calls
                            reason = "preceding-assignment"

            if funcs_to_audit:
                funcs_to_audit = {f for f in funcs_to_audit if f not in NEVER_FAILS}
            if funcs_to_audit:
                # Look for any OPS_* macro in the condition — if present,
                # the call is instrumented.
                if not re.search(r"\bOPS_\w+", cond):
                    snippet = cond.replace("\n", " ").strip()
                    snippet = re.sub(r"\s+", " ", snippet)
                    if len(snippet) > 90:
                        snippet = snippet[:87] + "..."
                    yield (path, i + 1, sorted(funcs_to_audit), snippet, reason)

            i = next_i
        else:
            i += 1


def main(argv):
    paths = [Path(p) for p in argv[1:]]
    if not paths:
        default = Path("interface/jni")
        if default.is_dir():
            paths = [default]
        else:
            print("usage: find-missing-jni-ops.py [paths ...]", file=sys.stderr)
            print("default path interface/jni/ not found from CWD", file=sys.stderr)
            return 2

    targets = []
    for p in paths:
        if p.is_dir():
            targets.extend(sorted(p.glob("*.c")))
        elif p.is_file() and p.suffix == ".c":
            targets.append(p)

    if not targets:
        print("no .c files matched", file=sys.stderr)
        return 2

    findings = []
    for t in targets:
        findings.extend(scan_file(t))

    if not findings:
        print(f"scanned {len(targets)} file(s); no missing JNI OPS instrumentation found")
        return 0

    by_file = {}
    for f in findings:
        by_file.setdefault(f[0], []).append(f)

    print(f"scanned {len(targets)} file(s); {len(findings)} potentially uninstrumented JNI "
          f"access check(s) in {len(by_file)} file(s):\n")
    for fpath in sorted(by_file):
        print(f"== {fpath}")
        for _, lineno, funcs, snippet, reason in by_file[fpath]:
            tag = "direct" if reason == "direct" else "after-assign"
            print(f"  {fpath}:{lineno}  [{tag}]  {', '.join(funcs)}")
            print(f"    if ({snippet})")
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
