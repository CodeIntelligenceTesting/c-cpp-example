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

void ExploreStructuredInputChecks(InputStruct inputStruct);