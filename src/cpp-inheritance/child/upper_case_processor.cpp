#include "upper_case_processor.h"

std::string UpperCaseProcessor::processData(const std::string& input) {
    std::string output = input;
    std::transform(output.begin(), output.end(), output.begin(), ::toupper);
    return output;
}