#include "metricA.h"

void MetricA::Set(int value) {
  value_ = value;
}

int MetricA::Get() const {
  return value_;
}

void MetricA::Reset() {
  value_ = 0;
}