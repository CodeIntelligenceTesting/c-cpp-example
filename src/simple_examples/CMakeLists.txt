set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_compile_options(-fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_library(explore_me
    explore_me.cpp
    utils.cpp
)

target_include_directories(explore_me PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OpenSSL_INCLUDE_DIR}
)

target_link_libraries(explore_me
    OpenSSL::Crypto
)

foreach(TestType IN ITEMS
    simple_checks
    complex_checks
)

    add_executable(${TestType}_test
        ${TestType}_test.cpp
    )

    target_include_directories(${TestType}_test PRIVATE
        ${CIFUZZ_INCLUDE_DIR}
    )

    target_link_libraries(${TestType}_test
        explore_me
        GTest::gtest_main
    )

    gtest_discover_tests(${TestType}_test)

    add_fuzz_test(${TestType}_fuzz_test
        ${TestType}_test.cpp
        TEST_FRAMEWORK 
        GTEST
    )

    target_link_libraries(${TestType}_fuzz_test
        explore_me
        GTest::gtest
    )
endforeach(TestType )
