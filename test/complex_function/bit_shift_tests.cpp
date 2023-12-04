//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "buffer_copy.h"

#ifdef __cplusplus
}
#endif

// Tests factorial of positive numbers.
TEST(BufferCopyTests, PositiveTest1) {
    char buffer[] = "Hello";
    char newBuffer[] = "Yippy";

    bufferCopy(buffer, newBuffer);
    EXPECT_EQ(buffer, newBuffer);
}

TEST(BufferCopyTests, PositiveTest2) {
    char buffer[] = "Hello";
    char newBuffer[] = "Ha";
    char resultBuffer[] = "Hallo";

    bufferCopy(buffer, newBuffer);
    EXPECT_EQ(buffer, resultBuffer);
}
