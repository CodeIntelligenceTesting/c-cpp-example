#pragma once
#include <string>
#include <utility>

#include "Publisher.h"
#include "metricB.h"

class PublisherB final : public Publisher {
public:
    // Constructor
    explicit PublisherB(std::string topic) : topic_(std::move(topic)) {}

    void Init() override;

    void Step() override;

    void PublishInput(const MetricB& metric, const std::string& message);

private:
    // Member variables
    std::string topic_;
};
