#ifndef RAND_UPCALL_H
#define RAND_UPCALL_H

#include <stdlib.h>


// FFI and JNI both implement this. Populate *out, return bytes filled.
// Negative return = error.
//
// Contract:
//   out_len:               must fill exactly. < = JO_RAND_UP_SHORT_RESULT.
//                          > = JO_RAND_ERROR (FFI: buffer already overrun).
//   strength:              advisory; bridge does not validate.
//   prediction_resistance: advisory; bridge does not validate.
//   adin / adin_len:       dropped on the floor by both bridges.
//   exceptions:            Java up-call must not throw. JNI bridge converts
//                          a leaked exception to JO_RAND_ERROR.
int rand_up_call_next_bytes(void * up_call_src, unsigned char *out, size_t out_len,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *adin, size_t adin_len);




#endif //RAND_UPCALL_H
