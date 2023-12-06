//
// Created by philip on 22/11/23.
//
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "bit_shifts.h"
extern "C" {
    #include "bit_shifts.h"
}

FUZZ_TEST_SETUP() {}


FUZZ_TEST(const uint8_t *data, size_t size) {

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);

    someBitShiftFunction(fdp.ConsumeIntegral<long>(), fdp.ConsumeIntegral<int>());
}