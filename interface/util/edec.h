//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#ifndef EDEC_H
#define EDEC_H
#include <stdint.h>

#include "key_spec.h"

int32_t edec_generate_key(key_spec *spec, int32_t type, void *rnd_src);

#endif //EDEC_H
