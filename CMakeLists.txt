cmake_minimum_required(VERSION 3.16)

project(AUTOMOTIVE-FUZZING-TESTSUITE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_fuzz_testing()
add_subdirectory(googletest)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

add_library(AUTOMOTIVE-FUZZING-TESTSUITE
        modules/crypto_module/src/crypto_module_1.c
        modules/crypto_module/src/crypto_module_2.c
        modules/time_module/src/time_module_1.c
        modules/GPS_module/src/GPS_module_1.c
        modules/key_management_module/src/key_management_module_1.c
        modules/example_module/src/person/person.c
        modules/example_module/src/person/person.h
        modules/example_module/src/buffer_copy/buffer_copy.c
        modules/example_module/src/buffer_copy/buffer_copy.h
        modules/example_module/src/complex_function/bit_shift/bit_shifts.c
        modules/example_module/src/complex_function/bit_shift/bit_shifts.h
)

target_include_directories(AUTOMOTIVE-FUZZING-TESTSUITE PRIVATE
        modules/crypto_module/src
        modules/time_module/src
        modules/key_management_module/src
        modules/GPS_module/src
)

add_fuzz_test(module_fuzzer test/generated_fuzz_test.cpp test/mocks.cpp)
target_link_libraries(module_fuzzer PRIVATE AUTOMOTIVE-FUZZING-TESTSUITE)
target_include_directories(module_fuzzer PRIVATE
        modules/crypto_module/src
        modules/time_module/src
        modules/key_management_module/src
        modules/GPS_module/src
)

add_executable(
        person_tests
        test/person/person_tests.cpp
)
target_link_libraries(
        person_tests
        GTest::gtest_main
        AUTOMOTIVE-FUZZING-TESTSUITE
)
target_include_directories(person_tests PRIVATE
        modules/example_module/src/person
        googletest/googletest/include
)

add_fuzz_test(person_fuzzer test/person/person_fuzz_test.cpp)
target_link_libraries(
        person_fuzzer
        AUTOMOTIVE-FUZZING-TESTSUITE
)
target_include_directories(person_fuzzer PRIVATE
        modules/example_module/src/person
        googletest/googletest/include
)

add_executable(
        buffer_copy_tests
        test/buffer_copy/buffer_copy_tests.cpp
)
target_link_libraries(
        buffer_copy_tests
        GTest::gtest_main
        AUTOMOTIVE-FUZZING-TESTSUITE
)
target_include_directories(buffer_copy_tests PRIVATE
        modules/example_module/src/buffer_copy
        googletest/googletest/include
)

add_fuzz_test(buffer_copy_fuzzer test/buffer_copy/buffer_copy_fuzz_test.cpp)
target_link_libraries(
        buffer_copy_fuzzer
        AUTOMOTIVE-FUZZING-TESTSUITE
)
target_include_directories(buffer_copy_fuzzer PRIVATE
        modules/example_module/src/buffer_copy
        googletest/googletest/include
)

add_executable(
        bit_shift_tests
        test/complex_function/bit_shift/bit_shift_tests.cpp
)
target_link_libraries(
        bit_shift_tests
        GTest::gtest_main
        AUTOMOTIVE-FUZZING-TESTSUITE
)
target_include_directories(bit_shift_tests PRIVATE
        modules/example_module/src/complex_function/bit_shift
        googletest/googletest/include
)

add_fuzz_test(bit_shift_fuzzer test/complex_function/bit_shift/bit_shift_fuzz_test.cpp)
target_link_libraries(
        bit_shift_fuzzer
        AUTOMOTIVE-FUZZING-TESTSUITE
)
target_include_directories(bit_shift_fuzzer PRIVATE
        modules/example_module/src/complex_function/bit_shift
        googletest/googletest/include
)

include(GoogleTest)
gtest_discover_tests(person_tests)
gtest_discover_tests(buffer_copy_tests)
gtest_discover_tests(bit_shift_tests)