set(OPENSSL_USE_STATIC_LIBS TRUE)


#option(LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF "Automatically download working protobuf" ON)
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
)

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
        explore_me_advanced
        ${GTEST_BOTH_LIBRARIES}
    )

    add_test(explore_me.${TestType} ${TestType}_test)

    add_fuzz_test(${TestType}_fuzz_test
        ${TestType}_test.cpp
    )

    target_link_libraries(${TestType}_fuzz_test
        explore_me_advanced
        ${GTEST_BOTH_LIBRARIES}
    )
endforeach(TestType )

add_custom_command(OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/mutator_data.pb.h
    ${CMAKE_CURRENT_BINARY_DIR}/mutator_data.pb.cc
    COMMAND protobuf::protoc mutator_data.proto
    --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
    --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
)

add_library(protobuf_mutator OBJECT
    ${CMAKE_CURRENT_BINARY_DIR}/mutator_data.pb.cc
)

target_include_directories(protobuf_mutator PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(protobuf_mutator PUBLIC
    protobuf-mutator-libfuzzer
    explore_me_advanced
)

add_fuzz_test(protobuf_mutator_example_fuzz_test protobuf_mutator_example_fuzz_test.cpp)
target_link_libraries(protobuf_mutator_example_fuzz_test explore_me_advanced protobuf_mutator)
target_link_options(protobuf_mutator_example_fuzz_test PRIVATE
    "-Wl,--copy-dt-needed-entries"
)