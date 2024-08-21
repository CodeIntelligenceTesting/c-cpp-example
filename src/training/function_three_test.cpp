#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"
#include <gtest/gtest.h>

TEST(ExploreSimpleChecksTests, DeveloperTest) {
  struct InputStruct inputStruct = { 0, 10, "Developer"};
  EXPECT_NO_THROW(FunctionThree(inputStruct));
}

TEST(ExploreSimpleChecksTests, MaintainerTest) {
  struct InputStruct inputStruct = { 20, -10, "Maintainer"};
  EXPECT_NO_THROW(FunctionThree(inputStruct));
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // transforming fuzzing data into the format we need for testing the target function
  FuzzedDataProvider fdp(data, size);
  struct InputStruct inputStruct = { 
    fdp.ConsumeIntegral<int>(),
    fdp.ConsumeIntegral<int>(), 
    fdp.ConsumeRemainingBytesAsString()
  };

  // calling the target function with the transformed fuzzing data
  FunctionThree(inputStruct);
}
