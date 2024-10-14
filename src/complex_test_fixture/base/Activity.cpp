#include "Activity.h"

#include <iostream>

void Activity::Init() {
    std::cout << "Activity::Init()" << std::endl;
}

void Activity::Step() {
    std::cout << "Activity::Step()" << std::endl;
    step_count_++;
    if (step_count_ > 10) {
        *(char *)0xdeadc0de = 0;
    }
    processStep();
}
