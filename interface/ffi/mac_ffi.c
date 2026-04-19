//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stddef.h>
#include <stdint.h>

#include "types.h"
#include "../util/mac.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"

uintptr_t MAC_new(const char *mac_name, const char *canonical_name, int32_t *err)
{
    uintptr_t out_ctx = 0;

    jo_assert(err != NULL);
    if (mac_name == NULL || canonical_name == NULL)
    {
        *err = JO_NAME_IS_NULL;
        return 0;
    }

    *err = jo_mac_new(mac_name, canonical_name, &out_ctx);
    if (*err < 0)
    {
        return 0;
    }

    return out_ctx;
}

int32_t MAC_init(uintptr_t ctx, uint8_t *key, size_t key_len)
{
    if (key == NULL)
    {
        return JO_KEY_IS_NULL;
    }
    return jo_mac_init(ctx, key, key_len);
}

int32_t MAC_update(uintptr_t ctx, uint8_t *input, size_t input_size, int32_t input_offset, int32_t input_len)
{
    if (input == NULL)
    {
        return JO_INPUT_IS_NULL;
    }
    if (input_offset < 0)
    {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (input_len < 0)
    {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (!check_in_range(input_size, (size_t)input_offset, (size_t)input_len))
    {
        return JO_INPUT_OUT_OF_RANGE;
    }
    return jo_mac_update(ctx, input, input_offset, input_len);
}

int32_t MAC_final(uintptr_t ctx, uint8_t *output, size_t output_size, int32_t output_offset)
{
    if (output == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if (output_offset < 0)
    {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    return jo_mac_final(ctx, output, output_offset, (int32_t)output_size);
}

int32_t MAC_len(uintptr_t ctx)
{
    return jo_mac_len(ctx);
}

void MAC_reset(uintptr_t ctx)
{
    jo_mac_reset(ctx);
}

void MAC_free(uintptr_t ctx)
{
    jo_mac_free(ctx);
}

uintptr_t MAC_copy(uintptr_t ctx, int32_t *err)
{
    uintptr_t out_ctx = 0;

    jo_assert(err != NULL);
    *err = jo_mac_copy(ctx, &out_ctx);
    if (*err < 0)
    {
        return 0;
    }

    return out_ctx;
}
