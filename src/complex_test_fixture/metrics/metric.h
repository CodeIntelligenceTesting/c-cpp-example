#pragma once

class Metric {
 public:
  virtual ~Metric() = default;
  virtual void Set(int value) = 0;
  virtual int Get() const = 0;
  virtual void Reset() = 0;
};