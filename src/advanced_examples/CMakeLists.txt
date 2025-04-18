set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
add_compile_options(-O0)

add_library(explore_me_advanced
    explore_me.cpp
)

target_include_directories(explore_me_advanced PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OpenSSL_INCLUDE_DIR}
)

target_link_libraries(explore_me_advanced
    OpenSSL::Crypto
    -lz
)

foreach(TestType IN ITEMS
    structured_input_checks
    slow_input_checks
)

    add_executable(${TestType}_test
        ${TestType}_test.cpp
    )

    target_include_directories(${TestType}_test PRIVATE
        ${CIFUZZ_INCLUDE_DIR}
    )

    target_link_libraries(${TestType}_test
        explore_me_advanced
        GTest::gtest_main
    )

    add_test(explore_me.${TestType} ${TestType}_test)

    add_fuzz_test(${TestType}_fuzz_test
        ${TestType}_test.cpp
        TEST_FRAMEWORK 
        GTEST
    )

    target_link_libraries(${TestType}_fuzz_test
        explore_me_advanced
        GTest::gtest        
    )
endforeach(TestType )
