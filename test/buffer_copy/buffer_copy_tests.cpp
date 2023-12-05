//
// Created by philip on 22/11/23.
//

#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>
#include "buffer_copy.h"


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
