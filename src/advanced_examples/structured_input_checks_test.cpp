#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

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
    int a = fdp.ConsumeIntegral<int>();
    int b = fdp.ConsumeIntegral<int>();
    std::string c = fdp.ConsumeRemainingBytesAsString();
    InputStruct inputStruct = (InputStruct) {.a=a, .b= b, .c=c};

    ExploreStructuredInputChecks(inputStruct);
}
