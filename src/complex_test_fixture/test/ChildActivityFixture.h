#pragma once

#include <gtest/gtest.h>

#include "metricA.h"
#include "metricB.h"

#include "PublisherA.h"
#include "PublisherB.h"

#include "SubscriberA.h"

#include "ChildActivity.h"

class ChildActivityFixture : public ::testing::Test {
public:

    explicit ChildActivityFixture();

    void Init();
    void Step();
    void SetPublisherInputMessages();

    void SetSomeFlagEnabled(bool enabled);

     // Members of different publisher types
    PublisherA publisherA{"topicA"};
    PublisherB publisherB{"topicB"};

    MetricA metricA{1};
    MetricB metricB{2};

    SubscriberA subscriberA{"topicA"};
    

    std::unique_ptr<ChildActivity> unit_{nullptr};

protected:
    void SetUp() override;
};