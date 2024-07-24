set(OPENSSL_USE_STATIC_LIBS TRUE)
option(LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF
        "Automatically download working protobuf" ON)
find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)
find_package(absl CONFIG)
include(libprotobuf-mutator)
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

protobuf_generate_cpp(
        PROTO_SRCS
        PROTO_HDRS
        mutator_data.proto
)

add_library(protobuf_mutator OBJECT
        ${PROTO_SRCS}
        ${PROTO_HDRS}
)

target_include_directories(protobuf_mutator PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LIB_PROTOBUF_MUTATOR_INCLUDE_DIR}
        ${Protobuf_INCLUDE_DIR}
)

target_link_libraries(protobuf_mutator PUBLIC
        ${Lib_Protobuf_Mutator_LIBRARIES}
        ${Protobuf_LIBRARIES}
        absl::log_internal_check_op
        explore_me_advanced
)

add_fuzz_test(protobuf_mutator_example_fuzz_test protobuf_mutator_example_fuzz_test.cpp)
target_link_libraries(protobuf_mutator_example_fuzz_test explore_me_advanced protobuf_mutator)
