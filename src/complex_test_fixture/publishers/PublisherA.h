#pragma once
#include <string>
#include <utility>

#include "Publisher.h"
#include "metricA.h"

class PublisherA final : public Publisher {
public:
    // Constructor
    explicit PublisherA(std::string topic) : topic_(std::move(topic)) {}

    void Init() override;

    void Step() override;

    void PublishInput(const MetricA& metric, const std::string& message);

private:
    // Member variables
    std::string topic_;
};
