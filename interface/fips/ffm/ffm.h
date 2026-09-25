//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef FFM_H
#define FFM_H
#include <stdbool.h>

#include "types.h"

/*
* Calls free on the passed in pointer.
* Use this in cases where security is not relevant, otherwise
* use the appropriate free for whatever you are doing.
*/
void JoFFM_freeUnsecureNullSafe(void *ptr);




#endif //FFM_H
