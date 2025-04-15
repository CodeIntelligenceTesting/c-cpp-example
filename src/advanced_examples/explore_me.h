/*
 * Copyright (c) 2023 Code Intelligence GmbH
 *
 */

#pragma once

#include <string>
#include <stdint.h>
#include <stddef.h>

struct InputStruct {
    long a;
    long b;
    std::string c;
};

void ExploreStructuredInputChecks(InputStruct inputStruct);
void ExploreSlowInputsChecks(int a, int b);
