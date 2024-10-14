#pragma once

#include "metric.h"

class MetricA : public Metric {
 public:
  explicit MetricA(int value) : value_(value) {};
  virtual ~MetricA() = default;
  void Set(int value) override;
  int Get() const override;
  void Reset() override;

 private:
    int value_{0};
};