//
// Created by philip on 05/12/23.
//

#include <string.h>
#include "sha256_encoder.h"
#include "helpers/sha256.h"

extern "C" {
#include "sha256_encoder.h"
}

char* faulty_sha256_encode(unsigned char* buffer, size_t length) {

    char* tmp = base64_encode(buffer, length);


    if (prefix(tmp, "ADDADAA")) {
        // Do something stupid
        char test[1];
        strcpy(test, "123");
    }

    return tmp;
}

bool prefix(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}