#include "metricB.h"

void MetricB::Set(int value) {
  value_ = value;
}

int MetricB::Get() const {
  return value_;
}

void MetricB::Reset() {
  value_ = 0;
}