#pragma once

#include "Subscriber.h"

class SubscriberA : public Subscriber {
public:
    SubscriberA(std::string topic) : topic_(std::move(topic)) {};
    virtual ~SubscriberA() = default;

    void Init() override;

    void Step() override;

    void ReceiveInput(const std::string& message) override;
private:
    std::string topic_;
};



