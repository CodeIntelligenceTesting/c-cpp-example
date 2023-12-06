//
// Created by philip on 05/12/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_SHA256_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_SHA256_H

#include <stdbool.h>

bool simpleSHA256(void* input, unsigned long length, unsigned char* md);

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_SHA256_H
