//
// Created by philip on 22/11/23.
//

#include "person.h"

#include <gtest/gtest.h>


// Tests factorial of positive numbers.
TEST(PersonTests, PositiveTests) {
    Person person = {
            .name= "Philip Betzler",
            .secret = "I don't like broccoli.",
            .age = 28,
    };


    EXPECT_EQ(getPersonsName(&person), person.name);
    EXPECT_EQ(getPersonsAge(&person), person.age);
}
