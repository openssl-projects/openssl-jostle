//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE



#ifndef OPENSSL_FIPS_FFI_H
#define OPENSSL_FIPS_FFI_H

#include <stdint.h>
#include "types.h"


/*
 * Initialise this library's own global lib ctx with the OpenSSL FIPS module
 * + base provider (jostle_ctx_init_fips) and pin it to fips=yes default
 * properties. One-shot per library instance. Distinctly (JoFips_) named so
 * an nm audit trivially separates it from the base library's
 * set_openssl_module; FIPS FFI callers resolve this library's exports via a
 * library-scoped lookup, never the process-global loader lookup.
 */
int32_t JoFips_set_openssl_module(const char *module_dir, const char *prov_name,
                                  const char *config_path);


#endif //OPENSSL_FIPS_FFI_H
