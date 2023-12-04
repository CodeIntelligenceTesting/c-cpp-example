//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "gtest/gtest.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "buffer_copy.h"

#ifdef __cplusplus
}
#endif

FUZZ_TEST_SETUP() {}


FUZZ_TEST(const uint8_t *data, size_t size) {

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);

    char buffer [100];
    std::string testString = fdp.ConsumeRemainingBytesAsString();

    bufferCopy(buffer, testString.c_str());

}