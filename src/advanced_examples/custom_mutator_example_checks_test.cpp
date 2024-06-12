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
    EXPECT_NO_THROW(ExploreCustomMutatorExampleChecks(&inputStruct));
}

TEST(ExploreStructuredInputChecks, MaintainerTest) {
    InputStrut inputStruct = (InputStruct) {.a=20, .b= -10, .c=0};
    inputStruct.c = malloc(sizeof("Maintainer"));
    inputStruct.c_size = sizeof("Maintainer");
    EXPECT_NO_THROW(ExploreCustomMutatorExampleChecks(&inputStruct));
}

#endif

FUZZ_TEST(const uint8_t *data, size_t size) {
    SpecialRequirementsStruct* inputStruct = (SpecialRequirementsStruct*) data;
    ExploreCustomMutatorExampleChecks(inputStruct);

    free(inputStruct->c);
}


extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
    std::cout << "In custom mutator.\n";

    FuzzedDataProvider fdp(Data, Size);
    long a = fdp.ConsumeIntegral<long>();
    long b = fdp.ConsumeIntegral<long>();
    std::string tempC = fdp.ConsumeRemainingBytesAsString();
    size_t c_size = strlen(tempC.c_str()) +1;
    char* c = (char*) malloc(c_size);
    strncpy(c, tempC.c_str(), c_size);
    SpecialRequirementsStruct specialRequirementsStruct = (SpecialRequirementsStruct) {
        .a= a, .b=b, .c_size=c_size, .c= c
    };
    size_t size1 = sizeof(specialRequirementsStruct);

    if (MaxSize >= size1) {
        free(Data);
        Data = (uint8_t*) malloc (size1);
        std::memcpy(Data, &specialRequirementsStruct, size1);
        return sizeof(specialRequirementsStruct);
    } else {
        return MaxSize;
    }
}
