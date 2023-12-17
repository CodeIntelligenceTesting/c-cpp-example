#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>

#include "explore_me.h"

TEST(ExploreComplexChecksTests, DeveloperTest) {
  EXPECT_NO_THROW(ExploreComplexChecks(0, 10, "Developer"));
}

TEST(ExploreComplexChecksTests, MaintainerTest) {
  EXPECT_NO_THROW(ExploreComplexChecks(20, -10, "Maintainer"));
}
