include(FetchContent)

#find_package(Protobuf REQUIRED)

if(NOT Protobuf_FOUND)
    set(protobuf_BUILD_TESTS OFF)

    FetchContent_Declare(protobuf
        GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
        GIT_TAG        v27.1
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(protobuf)
endif()
