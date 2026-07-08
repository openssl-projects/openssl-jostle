//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

#ifndef RAND_UPCALL_H
#define RAND_UPCALL_H

#include <jni.h>

extern JavaVM *java_vm;
extern jclass target_class;
extern jmethodID target_method;


void rand_up_call_init_jni(JNIEnv *env);

#endif //RAND_UPCALL_H
