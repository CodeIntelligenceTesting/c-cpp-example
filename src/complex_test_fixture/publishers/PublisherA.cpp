#include "PublisherA.h"
#include <iostream>

void PublisherA::Init() {
    std::cout << "PublisherA.Init(" << topic_ << ")" << std::endl;
}

void PublisherA::Step() {
    std::cout << "PublisherA.Step(" << topic_ << ")" << std::endl;
}

void PublisherA::PublishInput(const MetricA& metric, const std::string& message) {
    std::cout << "PublisherA.PublishInput(" << topic_ << ", " << message << ")" << std::endl;
}
