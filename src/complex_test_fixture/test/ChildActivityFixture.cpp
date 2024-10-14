#include "ChildActivityFixture.h"

ChildActivityFixture::ChildActivityFixture() {
    std::cerr << "ChildActivityFixture constructor" << std::endl;
    unit_ = std::make_unique<ChildActivity>();
}


void ChildActivityFixture::SetUp() {
    Init();
}

void ChildActivityFixture::Init() {
    publisherA.Init();
    publisherB.Init();
    subscriberA.Init();
    unit_->Init();
}

void ChildActivityFixture::Step() {
    publisherA.Step();
    publisherB.Step();
    unit_->Step();
    subscriberA.Step();
}

void ChildActivityFixture::SetPublisherInputMessages() {
    publisherA.PublishInput(metricA, "messageA");
    publisherB.PublishInput(metricB, "messageB");
}

void ChildActivityFixture::SetSomeFlagEnabled(bool enabled) {

}
