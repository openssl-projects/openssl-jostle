# Native code guidance (`interface/`)

Conventions for the C bridge (`interface/jni`, `interface/ffi`) and the OpenSSL
abstraction layer (`interface/util`), plus the native-side bug classes to review
for. Auto-imported by CLAUDE.md.

## Native code conventions (`interface/`)

1. **Bridge layer (`interface/jni/`, `interface/ffi/`)** is the only layer that validates user-supplied inputs and surfaces failures as typed return codes. The bridge MUST do all of the following before calling util:
   1. **Null-check every user-supplied pointer** — strings (curve names, digest names), byte arrays, and native handles cast from `jlong` (JNI) or `size_t`/raw pointer (FFI). Each gets a typed return code (`JO_NAME_IS_NULL`, `JO_INPUT_IS_NULL`, `JO_KEY_SPEC_IS_NULL`, `JO_SIGNER_CTX_IS_NULL`, etc.). **Never `jo_assert` on a value derived from a Java/FFI caller.**
   2. **Range-check every user-supplied length** — sign (`< 0` → `JO_*_IS_NEGATIVE`), zero where zero is meaningless (`== 0` → `JO_*_IS_NEGATIVE`), and upper bound where the value will be cast to `int` downstream (`> INT32_MAX` → `JO_INPUT_TOO_LONG_INT32` / `JO_OUTPUT_TOO_LONG_INT32`).
   3. **Range-check offset+length pairs** against the buffer they index — FFI uses `check_in_range(size, off, len)`; JNI uses `check_bytearray_in_range(ctx, off, len)`. These compute the addition safely even when both operands approach `SIZE_MAX/2`.
   4. **Translate JNI/FFI access failures** — `load_bytearray_ctx` / `load_critical_ctx` / `GetStringUTFChars` returning failure → `JO_FAILED_ACCESS_*` / `JO_UNABLE_TO_ACCESS_NAME`.

   JNI **must** request critical pointers via JVM and surface failures explicitly; FFI **must** receive the full byte-array size as a parameter so it can do its own range checks. **Both layers must return identical error codes for identical inputs** — if FFI rejects a value, JNI rejects it too with the same code, and vice versa.

2. **Abstraction layer (`interface/util/`)** is the only place that calls OpenSSL. It maintains state in structs across the JCA new → init → update → final → reset lifecycle. Util **trusts** the bridge to have validated user-supplied inputs and asserts those preconditions as invariants (see point 5). That includes `rnd_src` — both JNI and FFI bridges null-check the RandSource on every entry point that takes one, so util just `jo_assert`s it. Util's only legitimate `if (X) return JO_*` patterns are:
   1. **State checks** on bridge-validated outer pointers — e.g. `spec->key == NULL` (the `spec` was validated by the bridge, but its inner `key` field may legitimately be unset on a freshly-allocated spec), `ctx->digest_ctx == NULL` (`JO_NOT_INITIALIZED`), `ctx->opp != EC_OP_SIGN` (`JO_UNEXPECTED_STATE`).
   2. **OpenSSL-output bounds** after a probe call — e.g. `if (sig_len > (size_t) INT32_MAX) return JO_OUTPUT_TOO_LONG_INT32;` after `EVP_DigestSignFinal(NULL, &sig_len)` or `EVP_PKEY_derive(NULL, &need)`. These are values OpenSSL returned to us; we validate them before casting back to `int32_t` for the Java return path.

   Anything else that looks like user-input validation in util is a bug — move it to the bridge. Older modules (e.g. `rsa.c`) may still have the legacy "util as safety net" form for `rnd_src`; that's pre-existing tech debt, not the rule for new code.

3. Functions returning a pointer take `int32_t *err` as the last parameter; everything else returns a status code (`bc_err_codes.h`). Negative codes are errors, non-negative are byte counts / success.
4. Use `get_global_jostle_ossl_lib_ctx()` when calling `EVP_*_fetch` / `EVP_*_new_from_name`. Never call OpenSSL with a `NULL` lib ctx — operations need the lib ctx that hosts the Java RAND bridge.
5. `jo_assert` is for catastrophic conditions only (allocation failure, internal invariant). **Never use it for user-supplied input** — user errors must surface as error codes the bridge layer translates to JCE exceptions. Concretely, in the util layer:
   1. **Every parameter the bridge has validated is asserted as an invariant**, not error-returned. That includes pointers (`spec`, `key`, `digest_name`, byte-array pointers, `ctx`) AND value bounds the bridge enforces (`scalar_len > 0 && scalar_len <= INT32_MAX`, `in_len <= INT32_MAX`, `sig_len <= INT32_MAX`). If a util-layer assert fires, it means the bridge skipped a check — programmer error, not user error.
   2. **The exceptions** that stay as `if (X) return JO_*` in util are listed in point 2 (rnd_src, state checks, OpenSSL-output bounds). Anything outside that list belongs in the bridge.
6. **Use `INT32_MAX` (not `INT_MAX`)** when the bound's intent is "fits in int32_t" — it pairs with the `JO_*_INT32` error code names, the `int32_t` parameter types crossing the bridge, and the `(int32_t)` casts on the way back to Java. `int` happens to be 32-bit on every platform we build for, but `INT32_MAX` makes the intent unambiguous. Reserve `INT_MAX` for bounds that genuinely depend on the platform `int` width (rare).
7. Operations-test macros (`OPS_FAILED_ACCESS_1`, `OPS_OPENSSL_ERROR_3`, `OPS_FAILED_INIT_2`, etc.) defined in `interface/util/ops.h` are placed inside conditionals so tests can fault-inject failure paths. They expand to `is_ops_set(N) ||` in OPS builds and to nothing otherwise; the `OPS_OFFSET_*` macros let tests differentiate between multiple call sites that produce the same error code.


### Hard-code security-critical OpenSSL parameters; pair with a runtime hard guard

When OpenSSL exposes a parameter that controls a security property the implementation depends on — even when its default already matches what we need — set it explicitly in our code via `EVP_PKEY_CTX_set_params` (or the equivalent setter). Defaults can change between OpenSSL releases, custom providers can override them, and someone editing the C code can flip a value "for diagnostics" without realising it weakens the implementation. The explicit set makes the intent unambiguous to anyone reading the source and survives all three of those drift modes.

This rule is narrowly about a value *we set* to pin a security property — an input we choose. It is the inverse of, not in conflict with, the rule that a fixed value OpenSSL *defines and reports* (digest size, DRBG strength, max request, key/block/signature/MAC lengths) must be **queried and cached, never transcribed** into a Java/C table (see "OpenSSL is the single source of truth for fixed values" in java-spi.md). The test: are we telling OpenSSL something, or asking it something? Telling → hard-code and guard, as below. Asking → query and cache.

The canonical example is RSA PKCS#1 v1.5 implicit rejection. `OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION` is documented in `provider-asym_cipher(7)` as "Set by default in OpenSSL providers" — and the Bleichenbacher mitigation in `rsa_pkcs1.c` depends on the synthetic-plaintext-on-padding-failure behaviour that the parameter enables. We set `implicit_rejection = 1` explicitly in `rsa_pkcs1_init` immediately after `EVP_PKEY_CTX_set_rsa_padding`, with a block comment naming the security property and forbidding any change to the value. Apply the same pattern to any future security-critical parameter (e.g. PSS salt-length sentinels, mode-specific KDF iteration minimums) that has a sensitive default.

Pair the explicit set with a **runtime hard-guard test** — a regular unit test that exercises the API at the JCE surface and asserts the security property still holds. The test must be designed to fail loudly if the property is removed; a passing-positive-only test (e.g. round-trip succeeds) doesn't catch a regression where the property was removed but the happy path still works. The canonical hard-guard test is `RSAPKCS1CipherTest.testPKCS1_ImplicitRejection_HardGuard`: it constructs a deliberately-tampered ciphertext, calls decrypt, and asserts no `BadPaddingException` is thrown — a behaviour that can ONLY be true when implicit rejection is on. Verify the guard works by temporarily disabling the property (set the parameter to 0), confirming the test fails, then reverting.

Test design caveat for implicit-rejection guards: implicit rejection only fires for PKCS#1 v1.5 *padding* failures, not *structural* failures. A ciphertext whose integer value exceeds the modulus `n` is rejected by `RSA_public_decrypt` *before* the padding check runs — the test sees `BadPaddingException` even on a healthy implementation. For a 2048-bit RSA modulus, byte 0 of the 256-byte ciphertext is the most-significant byte; XOR-tampering it has roughly 50% probability of pushing the integer value past `n`. Tests that rely on the "no exception" property MUST restrict random tampering to bytes 1..length-1 — those positions cannot push the value past the modulus (the largest possible change is bounded well below the modulus's top-byte gap). The PKCS#1 hard guard's `posLowerBound = 1` constraint exists for exactly this reason; a future test that drops it will flake at a 1-in-256-ish per-trial rate.

OAEP doesn't have implicit rejection because OAEP is IND-CCA2 secure by construction and doesn't need it. Any OAEP decrypt failure (padding-check or structural) maps to a single error code (`JO_INVALID_CIPHER_TEXT`) at the C boundary, which the bridge translates to `InvalidCipherTextException` (`extends OpenSSLException`) and the SPI further translates to JCE-canonical `BadPaddingException` at `engineDoFinal`. The pattern of "distinct C error code → typed runtime exception → JCE-canonical checked exception" is what lets NI-level callers (limit tests) catch the specific `InvalidCipherTextException` without losing the JCE contract. Use this pattern when you have a failure mode that callers will want to react to differently from generic OpenSSL errors.


### Review native code for the bug classes Java tests can't catch

Most security-critical bugs in this codebase live in C, not Java: the JNI bridges in `interface/jni/`, the FFI bridges in `interface/ffi/`, and the OpenSSL abstraction layer in `interface/util/`. A Java roundtrip test cannot catch a memory-safety incident in native code, and a function that silently produces wrong-but-self-consistent output sails through any positive-only test on either side of the boundary. Every native change should be reviewed for the following classes specifically.

**Logic errors and inverted conditions**

OpenSSL's API convention is "1 = success, 0 = failure" and the project standardised on `if (1 != EVP_X_op(...))` for clarity. A bare `if (EVP_X_op(...))` (without the `1 !=`) accepts both success AND the rare-but-legal case where the function returns a different positive value, and `if (!EVP_X_op(...))` reads as "if not success" but evaluates to `if zero` — fine for OpenSSL's binary returns but wrong for any function that can return -1 (some `EVP_PKEY_CTX_*` functions do, signalling "operation not supported"). Off-by-one bugs hide between `>=` vs `>` on length checks (rejecting a valid length, or accepting one byte too many), `< 0` vs `<= 0` returning the wrong sign on a length parameter, and goto-fallthrough where an error path falls into the success path because the cleanup block doesn't `return`. OpenSSL has hard order-of-call requirements: `EVP_PKEY_CTX_set_rsa_oaep_md` requires `set_rsa_padding(OAEP)` first; `EVP_DigestSignInit_ex` must precede any `EVP_DigestSignUpdate`. A misordering passes silently — both calls return 1 — but produces wrong output that only a cross-implementation parity test will surface.

**Missing return statements and pointer-vs-value confusion in returns**

A C function that falls off its end without returning is undefined behaviour but compiles cleanly, especially when an early `goto exit` is added later and the writer forgets that the path past `exit:` no longer reaches the `return ret_code;` because of an intervening control flow change. Audit every function that returns a value to confirm every path either returns or unconditionally branches to a label that returns. Watch also for **address-vs-value mix-ups** — returning `&local_var` (pointer to a stack object that's destroyed at `return`) when the function is supposed to return the value, or returning `&p` (address of the local pointer) when the contract is "return the heap pointer `p`". Pointer-to-pointer parameters compound this: `int32_t *err` is an out-parameter the caller writes through (`*err = JO_FAIL`); writing `err = JO_FAIL` instead loses the assignment to a local, leaves the caller's `err` slot untouched, and the function is now silently returning success-but-with-an-error-code-that-disappears.

**Dangling pointers and free-after-use**

The `set0_*` family of OpenSSL functions takes ownership on success but **NOT on failure** — `EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, len)` returning 0 leaves the caller still owning `label`, which is why `rsa_oaep.c` frees `label_copy` on the failure branch. After freeing a pointer, set it to NULL or zero out the field that holds it: the lifecycle structs in `interface/util/*.c` (e.g. `rsa_ctx`, `rsa_oaep_ctx`) are reused across init / update / final / reset, and a stale `digest_ctx` pointer in `rsa_ctx` after a previous `EVP_MD_CTX_free` is exactly the kind of double-free that surfaces as a SIGSEGV inside `libcrypto`. Watch also for pointers escaping their scope — a local buffer's address copied into a struct that outlives the function. Pointers to JNI byte-array contents (from `GetByteArrayElements` or critical regions) MUST be released before the function returns; the `bytearrays.h` / `byte_array_critical.h` ctx helpers exist so `release_*_ctx` always pairs with `load_*_ctx`.

**Things not freed during error handling**

The `goto exit` pattern requires every owned resource to be visible at the cleanup label and to have a NULL-tolerant freer. **Declare every resource pointer at the top of the function and initialise to NULL before any branch that could goto** — if validation fails on line 5 and gotos to exit on line 6, the cleanup at line 50 must not deref an uninitialised pointer (which is undefined behaviour with potentially security-relevant consequences). The standard freers (`EVP_PKEY_free`, `EVP_PKEY_CTX_free`, `EVP_MD_CTX_free`, `BN_free`, `BN_clear_free`, `OSSL_PARAM_BLD_free`, `OSSL_PARAM_free`, `OPENSSL_free`, `OPENSSL_clear_free`) all accept NULL, so calling them unconditionally at the cleanup label is safe. The non-obvious case: `OSSL_PARAM_BLD_to_param(bld)` returns a NEW `OSSL_PARAM*` independent of `bld` — both must be freed. Secret material (private exponents, prime factors, key bytes) goes through `BN_clear_free` / `OPENSSL_clear_free` to zero memory before release. JNI string handles from `GetStringUTFChars` need `ReleaseStringUTFChars` on every exit path — the `rsa_init_strings_load` / `rsa_init_strings_release` helper in `rsa_ni_jni.c` is the canonical pattern for paired allocate-and-release across multiple JNI strings.

**Caller-owned output parameters must be freed unconditionally, never gated on the return code**

A util function that returns heap output through a pointer-out-parameter (`uint8_t **out`, `OSSL_PARAM **`, an `EVP_PKEY **`) plus a separate status code hands the *caller* an ownership obligation on every path. The recurring trap is a bridge that frees that output only on the success branch — `if (UNSUCCESSFUL(ret)) { return ret; }` — silently assuming "the callee only allocates `*out` on success." That assumption is usually true (`ks_store`, like the `rsa_*` helpers, sets `*out` non-NULL only immediately before `return JO_SUCCESS`), but it is an invariant maintained in a *different function* that nothing enforces. The day someone refactors the callee to set `*out` and then hit a later error path without nulling it, the caller leaks the buffer — and the leak is invisible to every positive test, because the happy path still frees correctly. Because the standard freers are NULL-tolerant, the robust form costs nothing: free the out-parameter unconditionally before the error return, so it is a no-op when nothing was allocated and a cleanup when something was.

```c
ret = ks_store(ctx, &out, &out_len, ...);
if (UNSUCCESSFUL(ret) || out == NULL) {
    OPENSSL_clear_free(out, out_len);   /* no-op when out == NULL; frees if util ever allocates-then-errors */
    return ret;
}
```

The general principle: **a layer's memory-safety must never silently depend on an invariant maintained by another layer.** This is the inverse face of point 5 — where the bridge trusts util to have *validated an input*, that is a deliberate, documented contract; but where a caller trusts a callee to have *not allocated on failure*, that is an undocumented assumption that converts a future edit into a leak, so defend against it locally. The same fragility appears in every `*Len`-then-fetch pair that runs the same allocating helper twice (e.g. `JoKS_StoreLen` / `JoKS_Store`, which free `out` only after the success check). Audit every bridge entry point in `interface/jni/` and `interface/ffi/` that receives a callee out-parameter for this shape.

**Integer overflow / underflow and signed→unsigned casts**

Java `int` is signed; nearly every length / offset / count crossing the JNI boundary is a `jint`. A negative `jint` cast straight to `size_t` becomes ~2³¹ (or ~2⁶³ on 64-bit hosts), and is then large-but-positive — which passes any `len > 0` check, drives runaway allocations, or produces a `memcpy` that reads memory the caller never owned. **Always validate range checks before the cast**: `if (in_off < 0 || in_len < 0) return JO_INPUT_*_NEGATIVE;` precedes any `(size_t)` cast or pointer arithmetic. The FFI `check_in_range(size, off, len)` and JNI `check_bytearray_in_range(ctx, off, len)` helpers compute the addition safely even when both operands are near `SIZE_MAX/2`. `BN_num_bytes()` returns `int` but represents an unsigned magnitude — a negative return signals an OpenSSL internal error and must be checked, not blindly cast to `size_t`. Allocations of the form `n * sizeof(T)` need an upper bound on `n` to avoid wraparound; same for `len + 16` style allocations where `len` could be near `INT32_MAX`. On the way back to Java, casting a `size_t` back to `jint` requires an explicit `> INT32_MAX` check — see `JO_OUTPUT_TOO_LONG_INT32` and `JO_INPUT_TOO_LONG_INT32` in `bc_err_codes.h`. Per the "Native code conventions" point 6: use `INT32_MAX`, not `INT_MAX`, anywhere the intent is "fits in int32_t".

**String functions without bounds**

`strcpy`, `strcat`, `sprintf`, and `gets` are banned outright. `strlen` on untrusted input is fine when the buffer is statically sized or NUL-termination is guaranteed by a producer (e.g. `GetStringUTFChars`'s return), but never on a raw network-, file-, or test-derived buffer that might lack a terminator. `strncpy` does NOT NUL-terminate when the source length ≥ destination size — explicitly write the trailing NUL or use `snprintf` instead. The `strncmp` size argument trips reviewers regularly: `strncmp(name, "FOO", sizeof("FOO"))` is **strict equality** because `sizeof("FOO")` includes the NUL terminator (4 chars total), so the comparison only succeeds when `name` is also exactly "FOO" (its 4th byte matches the literal's `\0`). `strncmp(name, "FOO", strlen("FOO"))` is a **prefix match** (3 chars, no NUL) and would accept "FOOBAR". The codebase uses the `sizeof` form deliberately for equality (e.g. `mac.c` checking `mac_name == "CMAC"`); a switch from `sizeof` to `strlen` silently changes the semantics.

**Side-channel and constant-time on secret data**

This is a crypto library; "wrong but consistent" answers turn into compromise vectors when an attacker can time the call. `memcmp(tag, expected, len)` short-circuits on the first mismatched byte and leaks the matched-prefix length to a network attacker — never use it for tag verification, MAC comparison, or password-hash check. Use `CRYPTO_memcmp` (OpenSSL's constant-time equivalent) instead. Similarly, avoid branching on a secret bit (`if (priv_key & 1)`), avoid indexing arrays with a secret value (cache-line timing leak), and avoid loops whose iteration count depends on a secret. The `rsa_pkcs1.c` Bleichenbacher mitigation — relying on OpenSSL's default implicit-rejection so decrypt failures emit a deterministic-length pseudo-random plaintext rather than an error — is one example of why this matters: a stricter `EVP_PKEY_decrypt` failure path that emitted distinct error codes for "wrong PKCS#1 marker" vs "wrong padding" would be a textbook padding oracle.

**JNI exception state and local-reference lifetime**

The `bytearrays.h` / `byte_array_critical.h` ctx helpers and `rsa_init_strings_load`/`_release` already handle `GetByteArrayElements`/`GetStringUTFChars` correctly, but JNI has two more failure modes that come up if a bridge ever needs to construct Java objects or run anything that can throw:

- **Pending exceptions silently propagate.** After any `(*env)->NewByteArray`, `(*env)->FindClass`, `(*env)->NewObject`, or upcall, an exception may be pending on `JNIEnv*`. Subsequent JNI calls during the same native invocation produce undefined behaviour — many will crash, some return invalid handles that segfault later. After a JNI call that can throw, `(*env)->ExceptionCheck(env)` and either `return` (letting the exception surface to Java) or `(*env)->ExceptionClear(env)` if the C side recovers.
- **Local refs accumulate inside loops.** `(*env)->NewByteArray`, `GetObjectArrayElement`, and constructor calls all return local refs that live until the JNI function returns. A loop that allocates ~1000+ local refs without `(*env)->DeleteLocalRef(env, ref)` exhausts the local-ref slot table — the JVM aborts. Long-running JNI loops should `DeleteLocalRef` per iteration or call `EnsureLocalCapacity` up-front.
- **`JNIEnv*` is per-thread and non-portable.** A pointer obtained on thread A is invalid on thread B. The current bridges don't pass `JNIEnv*` across threads, but a future native-callback path would need `(*jvm)->GetEnv(jvm, ...)` from each consumer thread.

**OpenSSL ERR-queue conventions**

OpenSSL maintains a thread-local error queue that operations push onto. Mismanagement leaks errors from one call into another's results.

- **`ERR_clear_error()` before any operation whose error you care about.** Otherwise a stale entry from a prior call surfaces as "the current error" in `OpenSSL.getOpenSSLErrors()`. Most `interface/util/*.c` functions clear the queue at the top of their main work block.
- **Mark/pop pairs balance.** `rsa.c::rsa_ctx_verify` uses `ERR_set_mark` + `ERR_pop_to_mark` (success or expected verify-fail) / `ERR_clear_last_mark` (genuine error) to scrub "signature didn't verify" noise without dropping real errors. Every `ERR_set_mark` must terminate via exactly one of those two functions on every code path including `goto exit`. A leaked mark is a permanent queue entry.
- **`pop_to_mark` honours nesting in order.** Nested marks pop their own scope; using `pop_to_mark` after the outer mark when the intent was the inner one silently keeps recent errors that should have been discarded.

**`OPS_*` macro hygiene (project-specific)**

The `OPS_FAILED_ACCESS_N`, `OPS_OPENSSL_ERROR_N`, `OPS_INT32_OVERFLOW_N`, `OPS_LEN_CHANGE_N`, etc. (defined in `interface/util/ops.h`) expand to either nothing (release build) or `is_ops_set(N) ||` (OPS build); the matching `OPS_OFFSET_*` macros expand to either nothing or `+ -<N>`. The idiosyncratic shape makes a few mistakes silent:

- **`OPS_*` must appear inside an `if` condition's expression, with whitespace between it and the next token.** `if (OPS_X expr)` is correct. `OPS_X if (expr)` and `OPS_X stmt;` either don't compile in OPS builds or silently no-op in release builds.
- **Pair the flag and the offset.** `if (OPS_OPENSSL_ERROR_2 cond) { ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1000); }` mixes flag `_2` with offset `_1` — tests targeting the `_2` site receive a different code than they expect.
- **Numeric offsets are part of the test contract.** `RSAOpsTest`, `RSAOAEPCipherOpsTest`, etc. assert exact return codes (`-1003`, `-2102`, `-2105`). Renumbering an offset in C without the test update is silent — the test sees a different (legitimate-looking) negative number and fails opaquely.
- **Each new fault-injection point needs a unique offset within its file's range.** `rsa.c` uses the 1000-block; `rsa_oaep.c` the 2000-block; `rsa_pkcs1.c` the 2100-block. Reusing an offset within a file collides on which call site failed; reusing across files is fine.

**Symbol-name collisions with libcrypto exports**

FFI exports are resolved by the dynamic loader against the union of `libinterface_ffi.dylib` and any other library already loaded in-process — including `libcrypto.dylib`. A C function named `RSA_sign` shadows libcrypto's own export of that name; depending on RTLD order, a call into "our" `RSA_sign` resolves to libcrypto's, producing impossible-looking SIGSEGVs inside libcrypto from what should be Jostle code. This was caught the hard way during initial RSA work — the fix was the `JoRSA_*` / `JoRSAOAEP_*` / `JoRSAPKCS1_*` prefix.

Use a `Jo*_` prefix on every FFI export. Verify before commit with `nm jostle/src/main/resources/native/<os>/<arch>/libinterface_ffi.dylib | grep ' T '` (Linux/macOS) and grep for any name that also appears in `nm "$OPENSSL_PREFIX/lib/libcrypto.3.dylib" | grep ' T '`. JNI exports use the JVM-mandated `Java_<class>_<method>` naming, so collision is a non-issue there.

**Thread-local entropy state and re-entrance**

`rand_set_java_srand_call(rnd_src)` writes a thread-local that the next OpenSSL operation consuming entropy reads. Two implications:

- **Within one native call, two operations that both set the thread-local race.** A future native function that calls into OpenSSL twice with different `rnd_src` values has the second `rand_set_java_srand_call` overwrite the first; the first OpenSSL call sees the second source. Currently no Jostle function does this; a refactor that consolidates two operations into one entry point needs to keep the order in mind.
- **The thread-local persists across calls on the same thread.** A thread that finished an RSA operation still has its `rand_src` pointer set when a later operation runs on it. The pointer references a Java `RandSource` whose lifetime is the duration of the original native call — reading it after the original call returned is use-after-free. Currently safe because every entropy-consuming OpenSSL call is preceded by a fresh `rand_set_java_srand_call`. Adding a code path that calls into OpenSSL without that prefix re-uses stale (possibly freed) state.

**Zeroize secrets with `OPENSSL_cleanse`, not `memset`**

The compiler is allowed to elide `memset(buf, 0, len)` if `buf` is freed (or its scope ends) immediately afterward — dead-store elimination. `OPENSSL_cleanse` (and the `BN_clear_free` / `OPENSSL_clear_free` allocators that wrap it) are written to be opaque to that optimization. For secret material — private exponents, prime factors, AES keys, post-decrypt plaintext, anything derived from a key — never use `memset` to zero before free.

**`memcpy` vs `memmove` for overlapping ranges**

`memcpy(dst, src, n)` with overlapping `dst`/`src` ranges is undefined behaviour even if the size is small and any sane implementation would happen to work. Two cases come up in this codebase:

- **Shifting a buffer onto itself.** `memcpy(buf, buf + offset, n)` when `offset < n` is the canonical violation. The GCM tag-buffer slide in `block_cipher_ctx.c` already uses `memmove` for this; copy that pattern for any new buffering code.
- **Aliased input/output via JNI.** A caller that passes the same byte array as both input and output to a native function exposes it twice through `GetByteArrayElements`; `memcpy(out, in, n)` is undefined when the underlying ranges coincide. The `java_bytearray_ctx` / `critical_bytearray_ctx` helpers handle one direction at a time, so this is structural rather than an active risk — but worth flagging if a future bridge starts doing in-place transforms.

