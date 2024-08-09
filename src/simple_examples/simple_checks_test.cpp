#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"
#include <gtest/gtest.h>


TEST(ExploreSimpleChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(ExploreSimpleChecks(0, 10, "Developer"));
}

TEST(ExploreSimpleChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(ExploreSimpleChecks(20, -10, "Maintainer"));
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  int a = fdp.ConsumeIntegral<int>();
  int b = fdp.ConsumeIntegral<int>();
  std::string c = fdp.ConsumeRemainingBytesAsString();

  ExploreSimpleChecks(a, b, c);
}
