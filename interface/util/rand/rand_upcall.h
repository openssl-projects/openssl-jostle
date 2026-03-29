#ifndef RAND_UPCALL_H
#define RAND_UPCALL_H

#include <stdlib.h>


//
// Needs to be implemented for both FFI and JNI.
// populate *out with random bytes.
// Return codes < 0 indicate some sort of issue.
// Note that if the java side throws and exception the JVM will terminate ungracefully.
//
int rand_up_call_next_bytes(void * up_call_src, unsigned char *out, size_t out_len,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *adin, size_t adin_len);




#endif //RAND_UPCALL_H
