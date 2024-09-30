#pragma once

#include <vector>
#include <string>
#include <iostream>

class DataProcessor {
public:
    void process(const std::vector<std::string>& data);

protected:
    virtual std::string processData(const std::string& input);
};
