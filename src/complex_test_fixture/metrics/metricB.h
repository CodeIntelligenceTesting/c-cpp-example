#pragma once

#include "metric.h"

class MetricB : public Metric {
 public:
  explicit MetricB(int value) : value_(value) {};
  virtual ~MetricB() = default;
  void Set(int value) override;
  int Get() const override;
  void Reset() override;

 private:
    int value_{0};
};