//
// Created by philip on 05/12/23.
//

#include <string.h>
#include <malloc.h>
#include <openssl/rand.h>
#include "sha256_encoder.h"
#include "helpers/sha256.h"

int faulty_sha256_encode(unsigned char* inputBuffer, size_t length, unsigned char** outputBuffer, unsigned char* key, unsigned char* iv) {

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    unsigned char tKey[AES_256_KEY_SIZE];
    /* Initialization Vector */
    unsigned char tIV[AES_BLOCK_SIZE];

    if (key != NULL) {
        strncpy(tKey, key, AES_256_KEY_SIZE);
    } else {
        RAND_bytes(key, sizeof(key));
    }

    if (iv != NULL) {
        strncpy(tIV, iv, AES_BLOCK_SIZE);
    } else {
        RAND_bytes(iv, sizeof(iv));
    }

    params->key = tKey;
    params->iv = tIV;

    /* Indicate that we want to encrypt */
    params->encrypt = 1;

    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_cbc();

    int encodedBufferLen = file_encrypt_decrypt(params, inputBuffer, outputBuffer);


    if (prefix(*outputBuffer, "ADDADAA")) {
        // Do something stupid
        char test[1];
        strcpy(test, "123");
    }

    cleanup(params);

    return encodedBufferLen;
}

bool prefix(const unsigned char *pre, const unsigned char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}
