//
// Created by philip on 05/12/23.
//



#include <openssl/sha.h>

extern "C" {
#include "sha256.h"
}

bool simpleSHA256(void* input, unsigned long length, unsigned char* md)
{
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return false;

    if(!SHA256_Update(&context, (unsigned char*)input, length))
        return false;

    if(!SHA256_Final(md, &context))
        return false;

    return true;
}