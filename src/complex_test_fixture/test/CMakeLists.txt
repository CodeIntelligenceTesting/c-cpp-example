add_executable(child_activity_test ChildActivityTest.cpp ChildActivityFixture.cpp)

# Link libraries
target_link_libraries(child_activity_test PRIVATE
    child_activity
    publishers
    subscribers
    GTest::gtest_main
)

# Add test to CTest
add_test(NAME ChildActivityTest COMMAND child_activity_test)
