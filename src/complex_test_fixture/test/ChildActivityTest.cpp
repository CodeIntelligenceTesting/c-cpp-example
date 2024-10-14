#include "ChildActivityFixture.h"

class ChildActivityTest : public ChildActivityFixture {
protected:
  void SetUp() override {
    ChildActivityFixture::SetUp();
  }

  void CheckResults(int value) {
    EXPECT_EQ(metricA.Get(), value);
  }
};

TEST_F(ChildActivityTest, Test1) {
    metricA.Set(1);
    SetPublisherInputMessages();
    Step();
    CheckResults(1);
}

TEST_F(ChildActivityTest, Test2) {
    metricA.Set(2);
    metricA.Reset();
    SetPublisherInputMessages();
    Step();
    CheckResults(0);
}