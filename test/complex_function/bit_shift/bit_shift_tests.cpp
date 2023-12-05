//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>
#include "bit_shifts.h"

// Tests factorial of positive numbers.
TEST(BitShiftTests, PositiveTest1) {
    long value = 8;
    int shiftingDistance = 1;
    EXPECT_EQ(someBitShiftFunction(value, shiftingDistance), 16);
}

TEST(BitShiftTests, PositiveTest2) {
    long value = 8;
    int shiftingDistance = 1;
    EXPECT_NE(someBitShiftFunction(value, shiftingDistance), 15);
}
