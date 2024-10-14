#pragma once
#include "Activity.h"

class ChildActivity final : public Activity {
public:
    ChildActivity();  

protected:
    void processStep() override;
};
