#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"
#include <gtest/gtest.h>

TEST(ExploreSimpleChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(FunctionOne(0, 10, "Developer"));
}

TEST(ExploreSimpleChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(FunctionOne(20, -10, "Maintainer"));
}

FUZZ_TEST(const uint8_t *data, size_t size) {

  // transforming fuzzing data into the format we need for testing the target function
  FuzzedDataProvider fdp(data, size);
  int a = fdp.ConsumeIntegral<int>();
  int b = fdp.ConsumeIntegral<int>();
  std::string c = fdp.ConsumeRemainingBytesAsString();

  // calling the target function with the transformed fuzzing data
  FunctionOne(a,b,c);
}
