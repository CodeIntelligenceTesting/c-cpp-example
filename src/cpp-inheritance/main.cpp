#include "upper_case_processor.h"
#include <vector>
#include <string>

int main() {
    std::vector<std::string> data = {"Hello", "World", "Data Processing"};

    UpperCaseProcessor processor;
    processor.process(data);

    return 0;
}
