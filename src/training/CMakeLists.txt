set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library(training_explore_me
    explore_me.cpp
    utils.cpp
)

target_include_directories(training_explore_me PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OpenSSL_INCLUDE_DIR}
)

target_link_libraries(training_explore_me
    OpenSSL::Crypto
)

foreach(TestType IN ITEMS
    function_one
    function_two
    function_three
)

    add_executable(${TestType}_test
        ${TestType}_test.cpp
    )

    target_include_directories(${TestType}_test PRIVATE
        ${CIFUZZ_INCLUDE_DIR}
    )

    target_link_libraries(${TestType}_test
        training_explore_me
        ${GTEST_BOTH_LIBRARIES}
    )

    add_test(training_explore_me.${TestType} ${TestType}_test)

    add_fuzz_test(${TestType}_fuzz_test
        ${TestType}_test.cpp
    )

    target_link_libraries(${TestType}_fuzz_test
        training_explore_me
        ${GTEST_BOTH_LIBRARIES}
    )
endforeach(TestType )
