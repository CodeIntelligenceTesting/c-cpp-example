#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "mutator_data.pb.h"
#include "port/protobuf.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/libfuzzer/libfuzzer_mutator.h"
#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

// The DEFINE_PROTO_FUZZER macro is used to define a fuzz test
// that receives a protobuf message as input. In this example,
// we created a protobuf message that corresponds to the input
// data that is received by a simple parser API.
DEFINE_PROTO_FUZZER(const fuzzing::DataStruct &input) {

}

