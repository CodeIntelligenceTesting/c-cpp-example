//
// Created by philip on 05/12/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_H

#include <stddef.h>

unsigned char *base64_decode(char* b64message, size_t *decode_len);
char *base64_encode(unsigned char *buffer, size_t length);

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_BASE64_H
