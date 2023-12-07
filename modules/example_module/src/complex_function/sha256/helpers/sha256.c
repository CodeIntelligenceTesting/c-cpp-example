//
// Created by philip on 05/12/23.
//



#include <openssl/sha.h>
#include <openssl/rand.h>
#include "sha256.h"
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>


void cleanup(cipher_params_t *params){
    free(params);
}


int file_encrypt_decrypt(cipher_params_t *params, unsigned char *inputBuffer, unsigned char** outputBuffer){
    /* Allow enough space in output inputBuffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);

    if (*outputBuffer != 0) {
        free(*outputBuffer);
    }

    int outputBufferLen = sizeof (unsigned char) * (BUFSIZE + cipher_block_size);
    *outputBuffer = (unsigned char *) malloc(outputBufferLen);


    int out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params);
    }

    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params);
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params);
    }


    // Read in data in blocks until EOF. Update the ciphering with each read.

    if(!EVP_CipherUpdate(ctx, *outputBuffer, &out_len, inputBuffer, strlen(inputBuffer))){
        fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params);
    }


    // Now cipher the final block and write it out to file
    if(!EVP_CipherFinal_ex(ctx, *&outputBuffer[out_len], &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params);
    }


    EVP_CIPHER_CTX_cleanup(ctx);
    return outputBufferLen;
}