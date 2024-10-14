#pragma once

#include <string>


class Publisher {
  public:
    Publisher() = default;
    virtual ~Publisher() = default;

    virtual void Init() = 0;
    virtual void Step() = 0;
};
