#include "ChildActivity.h"

#include <iostream>

ChildActivity::ChildActivity() {}

void ChildActivity::processStep() {
    std::cout << "ChildActivity::processStep()" << std::endl; 
}
