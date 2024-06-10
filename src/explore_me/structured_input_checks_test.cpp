#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreStructuredInputChecks, DeveloperTest) {
    InputStrut inputStrut = (InputStrut) {.a=0, .b= 10, .c="Developer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStrut));
}

TEST(ExploreStructuredInputChecks, MaintainerTest) {
    InputStrut inputStrut = (InputStrut) {.a=20, .b= -10, .c="Maintainer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStrut));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int a = fdp.ConsumeIntegral<int>();
    int b = fdp.ConsumeIntegral<int>();
    std::string c = fdp.ConsumeRemainingBytesAsString();
    InputStrut inputStrut = (InputStrut) {.a=a, .b= b, .c=c};

    ExploreStructuredInputChecks(inputStrut);
}
