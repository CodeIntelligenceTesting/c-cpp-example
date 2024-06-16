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
  FuzzedDataProvider fdp(data, size);
  long a = fdp.ConsumeIntegral<long>();
  long b = fdp.ConsumeIntegral<long>();
  size_t c_size = fdp.ConsumeIntegralInRange(1, 20);
  char* c = (char*) malloc(c_size);
  c[c_size-1] = '\0';

  FunctionTwo(a, b, c, c_size);
  free(c);
}
