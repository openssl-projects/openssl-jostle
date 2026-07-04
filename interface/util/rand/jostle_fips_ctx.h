//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

#ifndef JOSTLE_FIPS_CTX_H
#define JOSTLE_FIPS_CTX_H

#include "jostle_lib_ctx.h"

/**
 * Create a jostle_lib_ctx whose OSSL_LIB_CTX is backed by the OpenSSL FIPS
 * provider module plus the base provider (encoders/decoders), with the
 * lib ctx default properties pinned to "fips=yes" so every fetch resolves
 * only FIPS-approved algorithm implementations.
 *
 * The FIPS module is an OpenSSL provider module: it is located and dlopen'd
 * by libcrypto itself (via the module search path), NOT by the JVM.
 * Activation runs the module's integrity-MAC check and self-tests, driven
 * by the config file (a fipsinstall-generated fipsmodule.cnf defining
 * [fips_sect]) which this function wraps in a synthesised activating
 * configuration and loads into the new lib ctx.
 *
 * All file-path handling happens on the Java side (which has real path
 * APIs): the caller supplies the module's parent directory, the provider
 * name (module file name minus extension, e.g. fips.dylib -> "fips"), and
 * the resolved config path. The bridge layer validates the strings
 * (null/empty); util asserts them as invariants.
 *
 * Unlike jostle_ctx_init_new, NO java_rand_bridge provider is installed and
 * rand_ctx is left NULL: entropy stays inside the FIPS boundary, served by
 * the module's own approved DRBGs (auto-instantiated by OpenSSL on first
 * use of the lib ctx RAND).
 *
 * @param ctx          receiver of the new context; set to NULL on failure.
 * @param module_dir   directory containing the FIPS provider module; used
 *                     as the lib ctx module search path.
 * @param prov_name    the provider name OpenSSL maps to the module file
 *                     (e.g. "fips" for fips.dylib / fips.so / fips.dll).
 * @param config_path  filesystem path to the fipsinstall-generated config
 *                     (fipsmodule.cnf) carrying [fips_sect] with the
 *                     module-mac.
 * @return JO_SUCCESS, or one of the JO_FIPS_* codes (bc_err_codes.h):
 *         JO_FIPS_CONFIG_LOAD_FAILED   the config file is missing or fails
 *                                      to parse;
 *         JO_FIPS_PROVIDER_UNAVAILABLE the FIPS provider cannot be
 *                                      activated after config load - the
 *                                      module was not found on the search
 *                                      path, its integrity MAC did not match
 *                                      module-mac, or its self-tests failed
 *                                      (details on the ERR queue);
 *         JO_FIPS_BASE_UNAVAILABLE     the base provider is not available;
 *         JO_FIPS_ENABLE_FAILED        pinning default properties to
 *                                      fips=yes failed;
 *         JO_FIPS_FETCH_PROBE_FAILED   the post-init health probe (a
 *                                      fips=yes fetch) failed.
 *
 * (JO_FIPS_MODULE_PATH_INVALID is the bridge-level code for null/empty
 * path or name strings; it is not returned from here.)
 */
int32_t jostle_ctx_init_fips(jostle_lib_ctx **ctx, const char *module_dir,
                             const char *prov_name, const char *config_path);

#endif //JOSTLE_FIPS_CTX_H
