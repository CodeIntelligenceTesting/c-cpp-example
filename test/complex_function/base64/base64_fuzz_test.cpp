//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
    #include "base64_encoder.h"
}

FUZZ_TEST_SETUP() {}


FUZZ_TEST(const uint8_t *data, size_t size) {

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);
    std::string testString = fdp.ConsumeRemainingBytesAsString();

    faulty_base64_encode((unsigned char *) testString.c_str(), strlen(testString.c_str()));
}