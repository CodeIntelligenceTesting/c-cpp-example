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


#
# Block defining the location of the fuzzer_no_main library that is needed to compile this example
#

# Uncomment and change to your own path if you want to specify a specific fuzzer_no_main library
#set(FUZZER_NO_MAIN_PATH /usr/lib/clang/${CMAKE_C_COMPILER_VERSION}/lib/linux/libclang_rt.fuzzer_no_main-${CMAKE_SYSTEM_PROCESSOR}.a)


# If location is not manually defined, we search for it.
if (NOT DEFINED FUZZER_NO_MAIN_PATH)
    execute_process(COMMAND clang --print-file-name libclang_rt.fuzzer_no_main-${CMAKE_SYSTEM_PROCESSOR}.a 
        OUTPUT_VARIABLE FUZZER_NO_MAIN_PATH 
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # If the first search was not successful, we check if the dependency is there, but does not contain the architecture information
    # in its name, as it is common if you compile the sources yourself.
    if(NOT ${FUZZER_NO_MAIN_PATH} MATCHES "\/")
        execute_process(COMMAND clang --print-file-name libclang_rt.fuzzer_no_main.a 
            OUTPUT_VARIABLE FUZZER_NO_MAIN_PATH 
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()
endif()

#
# End of fuzzer_no_main definition
#

foreach(TestType IN ITEMS
    structured_input_checks
    custom_mutator_example_checks
)

    add_executable(${TestType}_test
        ${TestType}_test.cpp
    )

    target_include_directories(${TestType}_test PRIVATE
        ${CIFUZZ_INCLUDE_DIR}
    )

    target_link_libraries(${TestType}_test
        ${FUZZER_NO_MAIN_PATH}
        explore_me_advanced
        GTest::gtest_main
    )

    add_test(explore_me.${TestType} ${TestType}_test)

    add_fuzz_test(${TestType}_fuzz_test
        ${TestType}_test.cpp
    )

    target_link_libraries(${TestType}_fuzz_test
        ${FUZZER_NO_MAIN_PATH}
        explore_me_advanced
        GTest::gtest        
    )
endforeach(TestType )
