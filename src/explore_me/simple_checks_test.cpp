#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>

#include "explore_me.h"

TEST(ExploreSimpleChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(ExploreSimpleChecks(0, 10, "Developer"));
}

TEST(ExploreSimpleChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(ExploreSimpleChecks(20, -10, "Maintainer"));
}
