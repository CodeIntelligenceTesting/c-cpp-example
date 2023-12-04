//
// Created by philip on 22/11/23.
//
#include <stdint.h>
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "gtest/gtest.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "person.h"

#ifdef __cplusplus
}
#endif

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {

    // Ensure a minimum data length
    if (size < 100) return;

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);

    Person person = {
            .name = {*fdp.ConsumeBytesAsString(200).c_str()},
            .secret = {*fdp.ConsumeBytesAsString(200).c_str()},
            .age = fdp.ConsumeIntegral<int>(),

    };

    setPersonsName(&person, fdp.ConsumeBytesAsString(200).c_str());
    getPersonsName(&person);
    getPersonsAge(&person);


}