#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreComplexChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(FunctionTwo(0, 10, (char*) malloc(10), 10));
}

TEST(ExploreComplexChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(FunctionTwo(20, -10, (char*) malloc(11), 11));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
    // TODO write fuzz test yourself!
}
