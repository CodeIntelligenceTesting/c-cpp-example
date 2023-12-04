//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>

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

    int sizeBuffer = fdp.ConsumeIntegralInRange(0,200);
    char buffer [sizeBuffer];
    strncpy(buffer, fdp.ConsumeBytesAsString(sizeBuffer).c_str(), sizeBuffer);

    int sizeNewBuffer = fdp.ConsumeIntegralInRange(0,200);
    char newBuffer [sizeNewBuffer];
    strncpy(newBuffer, fdp.ConsumeBytesAsString(sizeNewBuffer).c_str(), sizeNewBuffer);

    char resultBuffer[sizeBuffer];
    strncpy(resultBuffer, buffer, sizeBuffer);
    strncpy(resultBuffer, newBuffer, sizeBuffer);

    bufferCopy(buffer, newBuffer);


    /*

    ASSERT_EQ(sizeof(buffer), sizeof(resultBuffer));
    for (int i = 0; i < sizeof(buffer); i++) {
        EXPECT_EQ(buffer[i], resultBuffer[i]);
    }
    */
}