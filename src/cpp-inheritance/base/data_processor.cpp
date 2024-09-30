#include "data_processor.h"

void DataProcessor::process(const std::vector<std::string>& data) {
    // Processed data storage
    std::vector<std::string> processedData;

    // Process each item using the virtual method
    for (const auto& item : data) {
        std::string result = processData(item);
        processedData.push_back(result);
    }

    // Output the results
    for (const auto& item : processedData) {
        std::cout << item << std::endl;
    }
}

std::string DataProcessor::processData(const std::string& input) {
    // Default implementation (could be empty or provide basic processing)
    return input;
}
