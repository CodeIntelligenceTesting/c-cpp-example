//
// Created by philip on 05/12/23.
//

#include "base64.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

/**
 * @brief Use the openssl library to decode a base64 string to a C string.
 *
 * @param[in] The Base64 encoded string. Has to null terminated.
 * @param[out] The length of the decoded string.
 *
 * @retval Pointer to decoded array of bytes. Note that array is not null-terminated.
 *         NULL if decoding failed.
 * 		   Caller has to free the memory after using the decoded string.
 */
unsigned char *base64_decode(char* b64message, size_t *decode_len)
{
    BIO *bio = NULL, *b64 = NULL;
    unsigned char *buffer = NULL;

    size_t msglen = strlen(b64message);

    if(msglen == 0) goto cleanup;

    bio = BIO_new_mem_buf(b64message, -1);
    if(bio == NULL) goto cleanup;
    b64 = BIO_new(BIO_f_base64());
    if(b64 == NULL) goto cleanup;

    // New lines should't matter
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_push(b64, bio);
    // The maximum possible length, after accounting for padding and CR+LF is msglen*3/4
    buffer = (unsigned char*) malloc(sizeof(char)*(msglen*3)/4);
    if (buffer == NULL) goto cleanup;

    *decode_len = (size_t) BIO_read(bio, buffer, (int) msglen);

    cleanup:
    BIO_free_all(bio);
    return buffer;
}

/**
 * @brief Use the openssl library to encode a byte array to a Base64 string.
 *
 * @param[in] The byte array to be encoded.
 * @param[in] The length of the byte array inputBuffer.
 *
 * @retval Pointer to encoded null-terminated string, or NULL if encoding failed.
 * 		   Caller has to free the memory after using the encoded string.
 */
char *base64_encode(unsigned char *buffer, size_t length)
{
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    char *b64text = NULL;

    if(length <= 0) goto cleanup;

    b64 = BIO_new(BIO_f_base64());
    if(b64 == NULL) goto cleanup;

    bio = BIO_new(BIO_s_mem());
    if(bio == NULL) goto cleanup;

    bio = BIO_push(b64, bio);

    if(BIO_write(bio, buffer, (int)length) <= 0) goto cleanup;

    if(BIO_flush(bio) != 1) goto cleanup;

    BIO_get_mem_ptr(bio, &bufferPtr);

    b64text = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
    if(b64text == NULL) goto cleanup;

    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';
    BIO_set_close(bio, BIO_NOCLOSE);

    cleanup:
    BIO_free_all(bio);
    free(bufferPtr);
    return b64text;
}