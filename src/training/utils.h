/*
 * Copyright (c) 2023 Code Intelligence GmbH
 *
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <string>

bool EqualsIgnoreCase(const std::string &a, const std::string &b);

std::string EncodeBase64(const std::string &input);

int min(int a, int b);