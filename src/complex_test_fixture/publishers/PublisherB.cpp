#include "PublisherB.h"
#include <iostream>

void PublisherB::Init() {
    std::cout << "PublisherB.init(" << topic_ << ")" << std::endl;
}

void PublisherB::Step() {
    std::cout << "PublisherB.step(" << topic_ << ")" << std::endl;
}

void PublisherB::PublishInput(const MetricB& metric, const std::string& message) {
    std::cout << "PublisherB.publish(" << topic_ << ", " << message << ")" << std::endl;
}
