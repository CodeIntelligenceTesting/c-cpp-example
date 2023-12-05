//
// Created by philip on 05/12/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_ENCODER_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_ENCODER_H

#include <stddef.h>
#include <stdbool.h>

char *faulty_base64_encode(unsigned char *buffer, size_t length);

bool prefix(const char *pre, const char *str);

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_ENCODER_H
