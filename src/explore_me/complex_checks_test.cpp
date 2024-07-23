#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreComplexChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(ExploreComplexChecks(0, 10, "Developer"));
}

TEST(ExploreComplexChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(ExploreComplexChecks(20, -10, "Maintainer"));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  long a = fdp.ConsumeIntegral<long>();
  long b = fdp.ConsumeIntegral<long>();
  std::string c = fdp.ConsumeRemainingBytesAsString();

  ExploreComplexChecks(a, b, c);
}
