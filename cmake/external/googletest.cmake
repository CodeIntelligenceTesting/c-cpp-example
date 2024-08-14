set(GTEST_TARGET external.googletest)
set(GTEST_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${GTEST_TARGET})

set(GTEST_INCLUDE_DIRS ${GTEST_INSTALL_DIR}/include)
include_directories(${GTEST_INCLUDE_DIRS})

set(GTEST_LIBRARIES gtest gmock)
set(GTEST_MAIN_LIBRARIES gtest_main)
set(GTEST_BOTH_LIBRARIES ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES})

foreach(lib IN LISTS GTEST_BOTH_LIBRARIES)
    if (MSVC)
        if (CMAKE_BUILD_TYPE MATCHES Debug)
            set(LIB_PATH ${GTEST_INSTALL_DIR}/lib/${lib}d.lib)
        else()
            set(LIB_PATH ${GTEST_INSTALL_DIR}/lib/${lib}.lib)
        endif()
    else()
        set(LIB_PATH ${GTEST_INSTALL_DIR}/lib/lib${lib}.a)
    endif()
    list(APPEND GTEST_BUILD_BYPRODUCTS ${LIB_PATH})

    add_library(${lib} STATIC IMPORTED)
    set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
            ${LIB_PATH})
    add_dependencies(${lib} ${GTEST_TARGET})
endforeach(lib)

include (ExternalProject)
ExternalProject_Add(${GTEST_TARGET}
        PREFIX ${GTEST_TARGET}
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
        UPDATE_COMMAND ""
        CMAKE_CACHE_ARGS -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}
        -DCMAKE_C_COMPILER_LAUNCHER:FILEPATH=${CMAKE_C_COMPILER_LAUNCHER}
        -DCMAKE_CXX_COMPILER_LAUNCHER:FILEPATH=${CMAKE_CXX_COMPILER_LAUNCHER}
        CMAKE_ARGS ${CMAKE_ARGS}
        -DCMAKE_INSTALL_PREFIX=${GTEST_INSTALL_DIR}
        -DCMAKE_INSTALL_LIBDIR=lib
        BUILD_BYPRODUCTS ${GTEST_BUILD_BYPRODUCTS}
)
