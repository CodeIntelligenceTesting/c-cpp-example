#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "explore_me.h"
#include <gtest/gtest.h>

TEST(ExploreSlowInputsChecks, FirstTest) {
    
    EXPECT_NO_THROW(ExploreSlowInputsChecks(23323, 100));
}

TEST(ExploreSlowInputsChecks, SecondTest) {
    EXPECT_NO_THROW(ExploreSlowInputsChecks(1324153, 192198));
}

DEBUG_FINDING(philosophical_capybara)
FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    long a = fdp.ConsumeIntegral<int>();
    long b = fdp.ConsumeIntegral<int>();
    ExploreSlowInputsChecks(a,b);
}
