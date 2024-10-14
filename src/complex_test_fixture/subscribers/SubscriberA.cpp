#include "SubscriberA.h"

#include <iostream>

void SubscriberA::Init() {
    std::cout << "SubscriberA.init(" << topic_ << ")" << std::endl;
}

void SubscriberA::Step() {
    std::cout << "SubscriberA.step(" << topic_ << ")" << std::endl;
}

void SubscriberA::ReceiveInput(const std::string& message) {
    std::cout << "SubscriberA.receive(" << topic_ << ", " << message << ")" << std::endl;
}