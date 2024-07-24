#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

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

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {

    static bool Printed;
    if (!Printed) {
        std::cerr << "In custom mutator.\n";
        Printed = true;
    }
    return 0; //LLVMFuzzerMutate(Data, Size, MaxSize);
}
