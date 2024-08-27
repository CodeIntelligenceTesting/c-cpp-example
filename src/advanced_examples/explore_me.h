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
void ExploreCompressedInputChecks(const uint8_t *Data, size_t Size);
void ExploreSlowInputsChecks(int a, int b);
