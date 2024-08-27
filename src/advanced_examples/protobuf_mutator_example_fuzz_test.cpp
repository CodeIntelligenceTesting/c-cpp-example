#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "mutator_data.pb.h"
#include "port/protobuf.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/libfuzzer/libfuzzer_mutator.h"
#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreStructuredInputChecks, DeveloperTest) {
    InputStruct inputStruct = (InputStruct) {.a=0, .b= 10, .c="Developer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStruct));
}

TEST(ExploreStructuredInputChecks, MaintainerTest) {
    InputStruct inputStruct = (InputStruct) {.a=20, .b= -10, .c="Maintainer"};
    EXPECT_NO_THROW(ExploreStructuredInputChecks(inputStruct));
}

#endif


// The DEFINE_PROTO_FUZZER macro is used to define a fuzz test
// that receives a protobuf message as input. In this example,
// we created a protobuf message that corresponds to the input
// data that is received by a simple parser API.
DEFINE_PROTO_FUZZER(const fuzzing::DataStruct &input) {
    InputStruct inputStruct = (InputStruct) {
            .a = input.a(),
            .b = input.b(),
            .c = input.c(),
    };
    ExploreStructuredInputChecks(inputStruct);
}

