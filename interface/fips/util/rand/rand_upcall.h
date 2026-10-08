#ifndef RAND_UPCALL_H
#define RAND_UPCALL_H

#include <stdlib.h>


// FFM and JNI both implement this. Populate *out, return bytes filled.
// Negative return = error.
//
// Contract:
//   out_len:               must fill exactly. < = JO_RAND_UP_SHORT_RESULT.
//                          > = JO_RAND_ERROR (FFM writes through reinterpret(len), never past it).
//   strength:              advisory; bridge does not validate.
//   prediction_resistance: advisory; bridge does not validate.
//   adin / adin_len:       dropped on the floor by both bridges.
//   exceptions:            converted to JO_RAND_ERROR: JNI in C, FFM in Java
//                          (RandSource.getRandomSegment), since C cannot catch one there.
int rand_up_call_next_bytes(void * up_call_src, unsigned char *out, size_t out_len,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *adin, size_t adin_len);




#endif //RAND_UPCALL_H
