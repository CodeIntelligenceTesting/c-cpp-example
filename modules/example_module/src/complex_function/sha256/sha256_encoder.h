//
// Created by philip on 05/12/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_ENCODER_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_ENCODER_H

#include <stddef.h>
#include <stdbool.h>

int faulty_sha256_encode(unsigned char* inputBuffer, size_t length, unsigned char** outputBuffer, unsigned char* key, unsigned char* iv);

bool prefix(const unsigned char *pre, const unsigned char *str);

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_ENCODER_H
