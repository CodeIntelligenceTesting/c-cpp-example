//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>


extern "C" {
    #include "sha256_encoder.h"
    #include "helpers/sha256.h"
}

FUZZ_TEST_SETUP() {}


FUZZ_TEST(const uint8_t *data, size_t size) {

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);
    std::string testString = fdp.ConsumeBytesAsString(200);

    unsigned char** encodedBuffer = static_cast<unsigned char **>(malloc(sizeof(unsigned char *)));

    faulty_sha256_encode(
            (unsigned char *) testString.c_str(),
            strlen(testString.c_str()),
            encodedBuffer,
            (unsigned char *) fdp.ConsumeBytesAsString(AES_256_KEY_SIZE).c_str(),
            (unsigned char *) fdp.ConsumeBytesAsString(AES_BLOCK_SIZE).c_str());
    free(encodedBuffer);
}