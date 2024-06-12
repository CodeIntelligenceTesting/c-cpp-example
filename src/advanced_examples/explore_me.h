/*
 * Copyright (c) 2023 Code Intelligence GmbH
 *
 */

#pragma once

#include <string>

struct InputStruct {
    long a;
    long b;
    std::string c;
};

struct SpecialRequirementsStruct {
    long a;
    long b;
    size_t c_size;
    char* c;
};

void ExploreStructuredInputChecks(InputStruct inputStrut);

void ExploreCustomMutatorExampleChecks(SpecialRequirementsStruct* specialRequirementsStruct);