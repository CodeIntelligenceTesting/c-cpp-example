//
// Created by philip on 05/12/23.
//

#include <string.h>
#include <malloc.h>
#include "sha256_encoder.h"
#include "helpers/sha256.h"

char* faulty_sha256_encode(unsigned char* buffer, size_t length) {

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));

    unsigned char* tmp = file_encrypt_decrypt(params, buffer, length);


    if (prefix(tmp, "ADDADAA")) {
        // Do something stupid
        char test[1];
        strcpy(test, "123");
    }

    cleanup(params);

    return tmp;
}

bool prefix(const unsigned char *pre, const unsigned char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}