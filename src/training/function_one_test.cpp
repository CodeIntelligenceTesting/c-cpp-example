#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreSimpleChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(FunctionOne(0, 10, "Developer"));
}

TEST(ExploreSimpleChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(FunctionOne(20, -10, "Maintainer"));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  int a = fdp.ConsumeIntegral<int>();
  int b = fdp.ConsumeIntegral<int>();
  std::string c = fdp.ConsumeRemainingBytesAsString();

  FunctionOne(a, b, c);
}
