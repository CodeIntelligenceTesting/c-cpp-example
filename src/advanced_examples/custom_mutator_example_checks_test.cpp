#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreStructuredInputChecks, DeveloperTest) {
    InputStruct inputStruct = (InputStrut) {.a=0, .b= 10, .c="Developer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStruct));
}

TEST(ExploreStructuredInputChecks, MaintainerTest) {
    InputStruct inputStruct = (InputStruct) {.a=20, .b= -10, .c="Maintainer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStruct));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    long a = fdp.ConsumeIntegral<long>();
    long b = fdp.ConsumeIntegral<long>();
    std::string c = fdp.ConsumeRemainingBytesAsString();

    InputStruct inputStruct = (InputStruct) {
            .a = a,
            .b = b,
            .c = c,
    };
    ExploreStructuredInputChecks(inputStruct);
}

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/**
Custom mutator example. In this case we only print out once that we are in a custom mutator and then use te regular one,
but you can also change the Data how you like. Make sure to return the new length.
*/
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {

    static bool Printed;
    if (!Printed) {
        std::cerr << "In custom mutator.\n";
        Printed = true;
    }

    // make sure to return the new Size (that needs to be <= MaxSize) as return value!
    return LLVMFuzzerMutate(Data, Size, MaxSize);
}
