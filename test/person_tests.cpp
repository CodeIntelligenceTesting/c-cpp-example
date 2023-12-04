//
// Created by philip on 22/11/23.
//
#include <stdint.h>
#include <stddef.h>

#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gtest/gtest.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "person.h"

#ifdef __cplusplus
}
#endif

FUZZ_TEST_SETUP() {}

// Tests factorial of positive numbers.
TEST(PersonTests, PositiveTests) {
    Person person = {
            "Philip Betzler",
            28,
            "I don't like broccoli."
    };


    EXPECT_EQ(getPersonsName(&person), person.name);
    EXPECT_EQ(getPersonsAge(&person), person.age);
}

FUZZ_TEST(const uint8_t *data, size_t size) {

    // Ensure a minimum data length
    if (size < 100) return;

    // Setup FuzzedDataProvider and initialize the mocklib
    FuzzedDataProvider fdp(data, size);

    Person person = {
            *fdp.ConsumeBytesAsString(200).c_str(),
            28,
            *fdp.ConsumeBytesAsString(200).c_str()
    };

    printPersonsName(&person);
    printPersonsAge(&person);


}