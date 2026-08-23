#ifndef RAND_PROV_H
#define RAND_PROV_H

#include <openssl/crypto.h>
#include <openssl/types.h>

#include "rand_upcall.h"

typedef struct jostle_lib_ctx {
    OSSL_LIB_CTX *ossl_libctx;
} jostle_lib_ctx;

/**
 * Create a new jostle_lib_ctx and set **rnd_ctx.
 * @param rnd_ctx receiver of the new context.
 * @param name the name of the OpenSSL module to load.
 * @return JO_SUCCESS or other JO_xx code.
 */
int32_t jostle_ctx_init_new(jostle_lib_ctx **rnd_ctx, const char *name);


/**
 * Free a jostle_lib_ctx: OSSL_LIB_CTX (unloads providers) and the wrapper
 * struct. Safe with NULL. Failure-path rollback only; not a general
 * teardown primitive.
 */
void jostle_ctx_destroy(jostle_lib_ctx *ctx);


/**
 * Set the global jostle FIPS lib ctx, expected to be called once
 * during java provider startup but does not enforce that.
 * Initialises a thread local
 * @param new_ctx
 * @return 1 on success
 */
int32_t set_global_jostle_fips_lib_ctx(jostle_lib_ctx *new_ctx);


/**
 * The lib ctx hosting the validated FIPS module, configured by
 * jostle_ctx_init_fips. Every EVP_*_fetch in this tree resolves through it.
 */
OSSL_LIB_CTX *get_global_jostle_fips_ossl_lib_ctx(void);


/*
 * FIPS-tree name separation - read this before renaming either accessor.
 *
 * The base tree names these set_global_jostle_lib_ctx /
 * get_global_jostle_ossl_lib_ctx. The FIPS tree names them apart and EVERY
 * caller in this tree spells the fips name at the call site - there is no
 * #define aliasing the base names onto them. Two properties follow:
 *
 *   1. The FIPS libraries define and export ONLY the fips-named symbols.
 *      There is no get_global_jostle_ossl_lib_ctx in interface_fips_jni or
 *      interface_fips_ffi for ELF load-order interposition to bind the base
 *      library's copy to, and none for a future FIPS-tree file to reach by
 *      accident. That is a property of the NAMES, so it holds on every
 *      platform and independently of the -Wl,-Bsymbolic on the FIPS targets
 *      (which stays: it covers the ~180 other shared util symbols).
 *
 *   2. Every fetch site in this tree NAMES the lib ctx it resolves through.
 *      Reading fips/util/rsa.c tells you it uses the FIPS lib ctx without
 *      having to know a header rewrote the call. An alias would have hidden
 *      exactly the fact this separation exists to make visible.
 *
 *   3. Because the base names are declared NOWHERE in this tree, a FIPS-tree
 *      source that spells one fails to COMPILE - "call to undeclared function
 *      'get_global_jostle_ossl_lib_ctx'", naming the file and line. Verified
 *      by sabotage. It cannot reach the base library's definition at load
 *      time, because it never gets as far as a link.
 *
 * The cost is that the ~20 util sources calling these are no longer
 * byte-for-byte twins of their nonfips counterparts. That is handled in
 * .claude/skills/audit-tree-parity/scripts/check-tree-parity.py, which
 * normalises this one rename before comparing, so those files are still
 * checked for every OTHER drift. Renaming an accessor here without updating
 * ACCESSOR_ALIASES there turns ~20 twins into unexplained drift.
 */

/**
 * Set the source of entropy for this call.
 *
 * @param target the target to get entropy from
 */
void rand_set_java_srand_call(void *target);

/**
 * Clear the per-thread RandSource up-call target. Every entry point that
 * binds a target with rand_set_java_srand_call MUST clear it before
 * returning: the target's lifetime is the duration of that native call (a
 * JNI local ref / an FFI arena-scoped stub), so a stale value read by a
 * future draw outside any entry point would be use-after-free. With the
 * target cleared, such a draw fails typed ("rand_src was null") instead.
 */
void rand_clear_java_srand_call(void);


#endif //RAND_PROV_H
