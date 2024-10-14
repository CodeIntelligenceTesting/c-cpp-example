#pragma once

class Activity {
public:
    Activity() = default;
    virtual ~Activity() = default;

    void Init();
    void Step();

protected:
    virtual void processStep() = 0; // Pure virtual function
private:
    int step_count_ = 0;
};
