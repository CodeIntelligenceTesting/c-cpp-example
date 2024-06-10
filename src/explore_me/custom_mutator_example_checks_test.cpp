#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "explore_me.h"

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <gtest/gtest.h>

TEST(ExploreCustomMutatorExampleChecks, DeveloperTest) {
    SpecialRequirementsStruct inputStruct = (SpecialRequirementsStruct) {.a=0, .b= 10, .c= 0, .c_size= 0};
    inputStruct.c = malloc(sizeof("Developer"));
    inputStruct.c_size = sizeof("Developer");
    EXPECT_NO_THROW(ExploreCustomMutatorExampleChecks(inputStruct));
}

TEST(ExploreStructuredInputChecks, MaintainerTest) {
    InputStrut inputStruct = (InputStruct) {.a=20, .b= -10, .c=0};
    inputStruct.c = malloc(sizeof("Maintainer"));
    inputStruct.c_size = sizeof("Maintainer");
    EXPECT_NO_THROW(ExploreCustomMutatorExampleChecks(inputStruct));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
    SpecialRequirementsStruct* inputStruct = (SpecialRequirementsStruct*) data;
    ExploreCustomMutatorExampleChecks(*inputStruct);

    free(inputStruct->c);
}


extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t maxSize, unsigned int seed) {
    FuzzedDataProvider fdp(data, size);
    long a = fdp.ConsumeIntegral<long>();
    long b = fdp.ConsumeIntegral<long>();
    const char* tempC = fdp.ConsumeRemainingBytesAsString().c_str();
    size_t c_size= strlen(tempC) +1;
    char* c = (char*) malloc(c_size);
    strncpy(c, tempC, c_size);
    SpecialRequirementsStruct specialRequirementsStruct = (SpecialRequirementsStruct) {
        .a= a, .b=b, .c_size=c_size, .c= c
    };

    free(data);
    data = (uint8_t*) malloc (sizeof(specialRequirementsStruct));
    std::memcpy(data, &specialRequirementsStruct, sizeof(specialRequirementsStruct));

    std::cout << "In custom mutator.\n";

    return sizeof(specialRequirementsStruct);
}
