include(FetchContent)

FetchContent_Declare(
        libprotobuf-mutator
        GIT_REPOSITORY https://github.com/google/libprotobuf-mutator.git
        GIT_TAG        master
        GIT_SHALLOW    TRUE
)
FetchContent_Populate(libprotobuf-mutator)

add_library(protobuf-mutator-libfuzzer
    ${libprotobuf-mutator_SOURCE_DIR}/src/binary_format.cc
    ${libprotobuf-mutator_SOURCE_DIR}/src/mutator.cc
    ${libprotobuf-mutator_SOURCE_DIR}/src/text_format.cc
    ${libprotobuf-mutator_SOURCE_DIR}/src/utf8_fix.cc
    ${libprotobuf-mutator_SOURCE_DIR}/src/libfuzzer/libfuzzer_mutator.cc
    ${libprotobuf-mutator_SOURCE_DIR}/src/libfuzzer/libfuzzer_macro.cc
)

target_include_directories(protobuf-mutator-libfuzzer PUBLIC
    ${libprotobuf-mutator_SOURCE_DIR}
)

target_link_libraries(protobuf-mutator-libfuzzer PUBLIC
    protobuf::libprotobuf
)
