//
// Created by philip on 05/12/23.
//

#ifndef AUTOMOTIVE_FUZZING_TESTSUITE_SHA256_H
#define AUTOMOTIVE_FUZZING_TESTSUITE_SHA256_H

#include <stdbool.h>
#include <openssl/types.h>


#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

void cleanup(cipher_params_t *params);

int file_encrypt_decrypt(cipher_params_t *params, unsigned char *inputBuffer, unsigned char** outputBuffer);

#endif //AUTOMOTIVE_FUZZING_TESTSUITE_SHA256_H
