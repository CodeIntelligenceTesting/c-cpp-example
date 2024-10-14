#pragma once

#include <string>

class Subscriber {
public:
    Subscriber() = default;
    virtual ~Subscriber() = default;

    virtual void Init() = 0;
    virtual void Step() = 0;
    virtual void ReceiveInput(const std::string& message) = 0;

};