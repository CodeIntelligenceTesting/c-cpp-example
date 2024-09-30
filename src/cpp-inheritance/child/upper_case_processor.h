#pragma once

#include "data_processor.h"
#include <algorithm>

class UpperCaseProcessor : public DataProcessor {
protected:
    std::string processData(const std::string& input) override;
};
