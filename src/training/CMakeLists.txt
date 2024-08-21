set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library(explore_me_training
    explore_me.cpp
    utils.cpp
)

target_include_directories(explore_me_training PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OpenSSL_INCLUDE_DIR}
)

target_link_libraries(explore_me_training
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
        explore_me_training
        GTest::gtest_main
    )

    add_test(explore_me_training.${TestType} ${TestType}_test)

    add_fuzz_test(${TestType}_fuzz_test
        ${TestType}_test.cpp
    )

    target_link_libraries(${TestType}_fuzz_test
        explore_me_training
        GTest::gtest
    )
endforeach(TestType )
