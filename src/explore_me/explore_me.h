/*
 * Copyright (c) 2023 Code Intelligence GmbH
 *
 */

#pragma once

#include <string>

struct InputStrut {
    long a;
    long b;
    std::string c;
};

void ExploreSimpleChecks(int a, int b, std::string c);

void ExploreComplexChecks(long a, long b, std::string c);

void ExploreStructuredInputChecks(InputStrut inputStrut);

void ExploreCustomMutatorExampleChecks(long a, long b, std::string c);