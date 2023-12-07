//
// Created by philip on 05/12/23.
//

#include <string.h>
#include "base64_encoder.h"
#include "helpers/base64.h"


char* faulty_base64_encode(unsigned char* buffer, size_t length) {

    char* tmp = base64_encode(buffer, length);

    if (tmp == NULL) {
        return NULL;
    }

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