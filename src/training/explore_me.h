/*
 * Copyright (c) 2023 Code Intelligence GmbH
 *
 */

#pragma once

#include <string>
#include <stdint.h>
#include <stddef.h>

struct InputStruct{
    int a;
    int b;
    std::string c;
};

void FunctionOne(int a, int b, std::string c);

void FunctionTwo(long a, long b, char* c, size_t size);

void FunctionThree(struct InputStruct inputStruct);